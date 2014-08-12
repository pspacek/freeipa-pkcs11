#include <Python.h>
#include "structmember.h"

#include <pkcs11.h>

#include "library.h"

// compat
#define CKM_AES_KEY_WRAP           (0x1090)

CK_BBOOL true = CK_TRUE;
CK_BBOOL false = CK_FALSE;

/**
 * IPA_PKCS11 type
 */
typedef struct {
	PyObject_HEAD
	CK_SLOT_ID slot;
	CK_FUNCTION_LIST_PTR p11;
	CK_SESSION_HANDLE session;
} IPA_PKCS11;

/**
 * IPA_PKCS11 Exceptions
 */
static PyObject *IPA_PKCS11Error;  //general error
static PyObject *IPA_PKCS11NotFound;  //key not found
static PyObject *IPA_PKCS11DuplicationError; //key already exists


/***********************************************************************
 * Support functions
 */

/**
 * Convert a unicode string to the utf8 encoded char array
 * @param unicode input python unicode object
 * @param l length of returned string
 * Returns NULL if an error occurs, else pointer to string
 */
char* unicode_to_char_array(PyObject *unicode, Py_ssize_t *l){
	PyObject* utf8_str = PyUnicode_AsUTF8String(unicode);
	if (utf8_str == NULL){
		PyErr_SetString(IPA_PKCS11Error, "Unable to encode UTF-8");
		return NULL;
	}
	Py_XINCREF(utf8_str);
	char* bytes = PyString_AS_STRING(utf8_str);
	if (bytes == NULL){
		PyErr_SetString(IPA_PKCS11Error, "Unable to get bytes from string");
		*l = 0;
	} else {
		*l = PyString_Size(utf8_str);
	}
	Py_XDECREF(utf8_str);
	return bytes;
}

/**
 * Tests result value of pkc11 operations
 * Returns 1 if everything is ok
 * Returns 0 if an error occurs and set the error message
 */
int check_return_value(CK_RV rv, const char *message) {
	char* errmsg = NULL;
	if (rv != CKR_OK) {
		if (asprintf(&errmsg, "Error at %s: 0x%x\n", message, (unsigned int) rv)
				== -1) {
			PyErr_SetString(IPA_PKCS11Error,
					"DOUBLE ERROR: Creating the error message caused an error");
			return 0; //
		}
		if (errmsg != NULL) {
			PyErr_SetString(IPA_PKCS11Error, errmsg);
			free(errmsg);
		}
		return 0;
	}
	return 1;
}

/*
 * Find key with specified attributes ('id' or 'label' and 'class' are required)
 *
 * id or label and class must be specified
 *
 * Function return only one key, if more keys meet the search parameters,
 * exception will be raised
 *
 * @param id key ID, (if value is NULL, will not be used to find key)
 * @param idLen key ID length
 * @param label key label (if value is NULL, will not be used to find key)
 * @param labelLen key label length
 * @param class key class
 * @param cka_wrap  (if value is NULL, will not be used to find key)
 * @param cka_unwrap (if value is NULL, will not be used to find key)
 * @param object
 * @return 1 if object was found, otherwise return 0 and set the exception
 *
 * @raise IPA_PKCS11NotFound if no result is returned
 * @raise IPA_PKCS11DuplicationError if more then 1 key meet the parameters
 */
int
_get_key(IPA_PKCS11* self, CK_BYTE_PTR id, CK_ULONG idLen,
		CK_BYTE_PTR label, CK_ULONG labelLen,
		CK_OBJECT_CLASS class, CK_BBOOL *cka_wrap,
		CK_BBOOL *cka_unwrap, CK_OBJECT_HANDLE *object)
{
	/* specify max number of possible attributes, increase this number whenever
	 * new attribute is added and don't forget to increase attr_count with each
	 * set attribute
	 */
	unsigned int max_possible_attributes = 5;
	CK_ATTRIBUTE template[max_possible_attributes];
	unsigned int attr_count = 0;

    CK_RV rv;
    if((label==NULL) && (id==NULL)){
    	PyErr_SetString(IPA_PKCS11Error, "Key 'id' or 'label' required.");
    	return 0;
    }
    if (label!=NULL){
    	template[attr_count].type = CKA_LABEL;
    	template[attr_count].pValue = (void *) label;
    	template[attr_count].ulValueLen = labelLen;
    	++attr_count;
    }
    if (id!=NULL){
    	template[attr_count].type = CKA_ID;
    	template[attr_count].pValue = (void *) id;
    	template[attr_count].ulValueLen = idLen;
    	++attr_count;
    }
    if (cka_wrap!=NULL){
    	template[attr_count].type = CKA_WRAP;
    	template[attr_count].pValue = (void *) cka_wrap;
    	template[attr_count].ulValueLen = sizeof(CK_BBOOL);
    	++attr_count;
    }
    if (cka_unwrap!=NULL){
    	template[attr_count].type = CKA_UNWRAP;
    	template[attr_count].pValue = (void *) cka_unwrap;
    	template[attr_count].ulValueLen = sizeof(CK_BBOOL);
    	++attr_count;
    }

    /* Set CLASS */
	template[attr_count].type = CKA_CLASS;
	template[attr_count].pValue = (void *) &class;
	template[attr_count].ulValueLen = sizeof(class);
	++attr_count;

    CK_ULONG objectCount;
    rv = self->p11->C_FindObjectsInit(self->session, template, attr_count);
    if(!check_return_value(rv, "Find key init"))
    	return 0;

    rv = self->p11->C_FindObjects(self->session, object, 1, &objectCount);
    if(!check_return_value(rv, "Find key"))
    	return 0;

    rv = self->p11->C_FindObjectsFinal(self->session);
    if(!check_return_value(rv, "Find objects final"))
    	return 0;
    //TODO objectCount comparation, should it be >1 ?
    if (objectCount == 0) {
    	PyErr_SetString(IPA_PKCS11NotFound, "Key not found");
    	return 0;
    }
    else if (objectCount > 1) { //TODO should be here NotFound error
    	PyErr_SetString(IPA_PKCS11DuplicationError, "_get_key: more than 1 key found");
    	return 0;
    }

    return 1;
}

/***********************************************************************
 * IPA_PKCS11 object
 */

static void IPA_PKCS11_dealloc(IPA_PKCS11* self) {
	self->ob_type->tp_free((PyObject*) self);
}

static PyObject *
IPA_PKCS11_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	IPA_PKCS11 *self;

	self = (IPA_PKCS11 *) type->tp_alloc(type, 0);
	if (self != NULL) {

		self->slot = 0;
		self->session = NULL;
		self->p11 = NULL;
	}

	return (PyObject *) self;
}

static int IPA_PKCS11_init(IPA_PKCS11 *self, PyObject *args, PyObject *kwds) {

	static char *kwlist[] = { NULL };
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "|", kwlist))
		return -1;

	return 0;
}

static PyMemberDef IPA_PKCS11_members[] = { { NULL } /* Sentinel */
};

/**
 * Initialization PKC11 library
 */
static PyObject *
IPA_PKCS11_initialize(IPA_PKCS11* self, PyObject *args) {
	const char* userPin = NULL;
	const char* libraryPath = NULL;
	CK_RV rv;
	void *moduleHandle = NULL;

	/* Parse method args*/
	if (!PyArg_ParseTuple(args, "iss", &self->slot, &userPin, &libraryPath))
		return NULL;

	CK_C_GetFunctionList pGetFunctionList = loadLibrary(libraryPath,
			&moduleHandle);
	if (!pGetFunctionList) {
		PyErr_SetString(IPA_PKCS11Error, "Could not load the library.");
		return NULL;
	}

	/*
	 * Load the function list
	 */
	(*pGetFunctionList)(&self->p11);

	/*
	 * Initialize
	 */
	rv = self->p11->C_Initialize(NULL);
	if (!check_return_value(rv, "initialize"))
		return NULL;

	/*
	 *Start session
	 */
	rv = self->p11->C_OpenSession(self->slot,
			CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &self->session);
	if (!check_return_value(rv, "open session"))
		return NULL;

	/*
	 * Login
	 */
	rv = self->p11->C_Login(self->session, CKU_USER, (CK_BYTE*) userPin,
			strlen((char *) userPin));
	if (!check_return_value(rv, "log in"))
		return NULL;

	return Py_None;
}

/*
 * Finalize operations with pkcs11 library
 */
static PyObject *
IPA_PKCS11_finalize(IPA_PKCS11* self) {
	CK_RV rv;

	/*
	 * Logout
	 */
	rv = self->p11->C_Logout(self->session);
	if (rv != CKR_USER_NOT_LOGGED_IN) {
		if (!check_return_value(rv, "log out"))
			return NULL;
	}

	/*
	 * End session
	 */
	rv = self->p11->C_CloseSession(self->session);
	if (!check_return_value(rv, "close session"))
		return NULL;

	/*
	 * Finalize
	 */
	self->p11->C_Finalize(NULL);

	self->p11 = NULL;
	self->session = NULL;
	self->slot = 0;

	return Py_None;
}

/********************************************************************
 * Methods working with keys
 */

/**
 * Generate master key
 *
 */
static PyObject *
IPA_PKCS11_generate_master_key(IPA_PKCS11* self, PyObject *args, PyObject *kwds)
{
    CK_RV rv;
    CK_OBJECT_HANDLE symKey;
    CK_BYTE *id = NULL;
    int id_length = 0;
    CK_ULONG keyLength = 16;
    PyObject *labelUnicode = NULL;
    Py_ssize_t label_length = 0;
	static char *kwlist[] = {"subject", "id", "key_length", NULL };
	//TODO check long overflow
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "Us#|k", kwlist,
			&labelUnicode, &id, &id_length, &keyLength)){
		return NULL;
	}

	Py_XINCREF(labelUnicode);
	CK_BYTE *label = (unsigned char*) unicode_to_char_array(labelUnicode, &label_length); //TODO verify signed/unsigned
	Py_XDECREF(labelUnicode);
    CK_MECHANISM mechanism = { //TODO param?
         CKM_AES_KEY_GEN, NULL_PTR, 0
    };
    CK_ATTRIBUTE symKeyTemplate[] = {
         {CKA_ID, id, id_length},
         {CKA_LABEL, label, label_length},
         {CKA_TOKEN, &true, sizeof(true)}, //TODO param?
         {CKA_PRIVATE, &true, sizeof(true)}, //TODO param?
         {CKA_ENCRYPT, &false, sizeof(false)}, //TODO param?
         {CKA_DECRYPT, &false, sizeof(false)}, //TODO param?
         {CKA_VERIFY, &false, sizeof(false)}, //TODO param?
         {CKA_WRAP, &true, sizeof(true)}, //TODO param?
         {CKA_UNWRAP, &true, sizeof(true)}, //TODO param?
         {CKA_EXTRACTABLE, &true, sizeof(true)}, //TODO param?
         {CKA_VALUE_LEN, &keyLength, sizeof(keyLength)}
    };

    //TODO if key exists raise an error????

    rv = self->p11->C_GenerateKey(self->session,
                           &mechanism,
                           symKeyTemplate,
			    sizeof(symKeyTemplate)/sizeof(CK_ATTRIBUTE),
                           &symKey);
    if(!check_return_value(rv, "generate master key"))
    	return NULL;

	return Py_None;
}


/**
 * Generate replica keys
 *
 */
static PyObject *
IPA_PKCS11_generate_replica_key_pair(IPA_PKCS11* self, PyObject *args, PyObject *kwds)
{
    CK_RV rv;
    CK_ULONG modulusBits = 2048;
    CK_BYTE *id = NULL;
    int id_length = 0;
    PyObject* labelUnicode = NULL;
    Py_ssize_t label_length = 0;
	static char *kwlist[] = {"subject", "id", "modulus_bits", NULL };
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "Us#|k", kwlist,
			&labelUnicode, &id, &id_length, &modulusBits)){
		return NULL;
	}

	Py_XINCREF(labelUnicode);
	CK_BYTE *label = unicode_to_char_array(labelUnicode, &label_length);
	Py_XDECREF(labelUnicode);

    CK_OBJECT_HANDLE publicKey, privateKey;
    CK_MECHANISM mechanism = {
         CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
    };

    //TODO raise an exception if key exists

    CK_BYTE publicExponent[] = { 1, 0, 1 }; /* 65537 (RFC 6376 section 3.3.1)*/
    CK_ATTRIBUTE publicKeyTemplate[] = {
         {CKA_ID, id, id_length},
         {CKA_LABEL, label, label_length},
         {CKA_TOKEN, &true, sizeof(true)}, //TODO param?
         {CKA_WRAP, &true, sizeof(true)}, //TODO param?
         {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)}, //TODO param
         {CKA_PUBLIC_EXPONENT, publicExponent, 3},
    };
    CK_ATTRIBUTE privateKeyTemplate[] = {
         {CKA_ID, id, id_length},
         {CKA_LABEL, label, label_length},
         {CKA_TOKEN, &true, sizeof(true)}, //TODO param?
         {CKA_PRIVATE, &true, sizeof(true)}, //TODO param?
         {CKA_SENSITIVE, &false, sizeof(false)}, // prevents wrapping
         	 	 	 	 	 	 	 	 	 	 //TODO param?
         {CKA_UNWRAP, &true, sizeof(true)}, //TODO param?
         {CKA_EXTRACTABLE, &true, sizeof(true)}, //TODO param?
         {CKA_WRAP_WITH_TRUSTED, &false, sizeof(false)} // prevents wrapping
         	 	 	 	 	 	 	 	 	 	 //TODO param?
    };

    rv = self->p11->C_GenerateKeyPair(self->session,
                           &mechanism,
                           publicKeyTemplate,
			    sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE),
                           privateKeyTemplate,
			    sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE),
                           &publicKey,
                           &privateKey);
    if(!check_return_value(rv, "generate key pair"))
    	return NULL;

	return Py_None;
}

/**
 * Find key
 *
 * Default class: public_key
 *
 */
static PyObject *
IPA_PKCS11_get_key_handler(IPA_PKCS11* self, PyObject *args, PyObject *kwds)
{
    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_BYTE *id = NULL;
    CK_BBOOL *ckawrap = NULL;
    CK_BBOOL *ckaunwrap = NULL;
    int id_length = 0;
    CK_ULONG keyLength = 16;
    PyObject *labelUnicode = NULL;
    PyObject *ckaWrapBool = NULL;
    PyObject *ckaUnwrapBool = NULL;
    Py_ssize_t label_length = 0;
	static char *kwlist[] = {"class", "label", "id", "cka_wrap", "cka_unwrap", NULL };
	//TODO check long overflow
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "i|Uz#OO", kwlist,
			 &class, &labelUnicode, &id, &id_length, &keyLength,
			 &ckaWrapBool, &ckaUnwrapBool)){
		return NULL;
	}

	CK_BYTE *label = NULL;
	if (labelUnicode != NULL){
		Py_INCREF(labelUnicode);
		label = (unsigned char*) unicode_to_char_array(labelUnicode, &label_length); //TODO verify signed/unsigned
		Py_DECREF(labelUnicode);
	}

	if(ckaWrapBool!=NULL){
		Py_INCREF(ckaWrapBool);
		if (PyObject_IsTrue(ckaWrapBool)){
			ckawrap = &true;
		} else {
			ckawrap = &false;
		}
		Py_DECREF(ckaWrapBool);
	}

	if(ckaUnwrapBool!=NULL){
		Py_INCREF(ckaUnwrapBool);
		if (PyObject_IsTrue(ckaWrapBool)){
			ckawrap = &true;
		} else {
			ckawrap = &false;
		}
		Py_DECREF(ckaUnwrapBool);
	}

	CK_OBJECT_HANDLE object = 0;
	if(! _get_key(self, id, id_length, label, label_length, class, ckawrap,
			ckaunwrap, &object))
		return NULL;

	return Py_BuildValue("k",object);
}

/**
 * delete key
 */
static PyObject *
IPA_PKCS11_delete_key(IPA_PKCS11* self, PyObject *args, PyObject *kwds)
{
	CK_RV rv;
    CK_OBJECT_HANDLE key_handler = 0;
	static char *kwlist[] = {"key_handler", NULL };
	//TODO check long overflow
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "k|", kwlist,
			 &key_handler)){
		return NULL;
	}
	rv = self->p11->C_DestroyObject(self->session, key_handler);
	if(!check_return_value(rv, "object deletion")){
		return NULL;
	}

	return Py_None;
}

/**
 * export secret key
 */
static PyObject *
IPA_PKCS11_export_secret_key(IPA_PKCS11* self, PyObject *args, PyObject *kwds)
{
	CK_RV rv;
	CK_UTF8CHAR_PTR value = NULL;
    CK_OBJECT_HANDLE key_handler = 0;
    PyObject *ret = NULL;
	static char *kwlist[] = {"key_handler", NULL };
	//TODO check long overflow
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "k|", kwlist,
			 &key_handler)){
		return NULL;
	}

	//TODO which attributes should be returned ????
    CK_ATTRIBUTE obj_template[] = {
         {CKA_VALUE, NULL_PTR, 0}
    };

    rv = self->p11->C_GetAttributeValue(self->session, key_handler, obj_template, 1);
    if (!check_return_value(rv, "get attribute value - prepare")){
    	return NULL;
    }

    /* Set proper size for attributes*/
    value = (CK_UTF8CHAR_PTR) malloc(obj_template[0].ulValueLen * sizeof(CK_BYTE));
    obj_template[0].pValue = value;

    rv = self->p11->C_GetAttributeValue(self->session, key_handler, obj_template, 1);
    if (!check_return_value(rv, "get attribute value")){
    	free(value);
    	return NULL;
    }

    if (obj_template[0].ulValueLen <= 0){
    	PyErr_SetString(IPA_PKCS11NotFound, "Value not found");
    	free(value);
    	return NULL;
    }
    ret = Py_BuildValue("{s:s#}",
    		"value", obj_template[0].pValue, obj_template[0].ulValueLen);
    free(value);
	return ret;
}

static PyMethodDef IPA_PKCS11_methods[] = {
		{ "initialize",
		(PyCFunction) IPA_PKCS11_initialize, METH_VARARGS,
		"Inicialize pkcs11 library" },
		{ "finalize",
		(PyCFunction) IPA_PKCS11_finalize, METH_NOARGS,
		"Finalize operations with pkcs11 library" },
		{ "generate_master_key",
		(PyCFunction) IPA_PKCS11_generate_master_key, METH_VARARGS|METH_KEYWORDS,
		"Generate master key" },
		{ "generate_replica_key_pair",
		(PyCFunction) IPA_PKCS11_generate_replica_key_pair, METH_VARARGS|METH_KEYWORDS,
		"Generate replica key pair" },
		{ "get_key_handler",
		(PyCFunction) IPA_PKCS11_get_key_handler, METH_VARARGS|METH_KEYWORDS,
		"Find key" },
		{ "delete_key",
		(PyCFunction) IPA_PKCS11_delete_key, METH_VARARGS|METH_KEYWORDS,
		"Delete key" },
		{ "export_secret_key",
		(PyCFunction) IPA_PKCS11_export_secret_key, METH_VARARGS|METH_KEYWORDS,
		"Export secret key" },
		{ NULL } /* Sentinel */
};

static PyTypeObject IPA_PKCS11Type = {
	PyObject_HEAD_INIT(NULL)
	0, /*ob_size*/
	"ipa_pkcs1.IPA_PKCS11", /*tp_name*/
	sizeof(IPA_PKCS11), /*tp_basicsize*/
	0, /*tp_itemsize*/
	(destructor)IPA_PKCS11_dealloc, /*tp_dealloc*/
	0, /*tp_print*/
	0, /*tp_getattr*/
	0, /*tp_setattr*/
	0, /*tp_compare*/
	0, /*tp_repr*/
	0, /*tp_as_number*/
	0, /*tp_as_sequence*/
	0, /*tp_as_mapping*/
	0, /*tp_hash */
	0, /*tp_call*/
	0, /*tp_str*/
	0, /*tp_getattro*/
	0, /*tp_setattro*/
	0, /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
	"IPA_PKCS11 objects", /* tp_doc */
	0, /* tp_traverse */
	0, /* tp_clear */
	0, /* tp_richcompare */
	0, /* tp_weaklistoffset */
	0, /* tp_iter */
	0, /* tp_iternext */
	IPA_PKCS11_methods, /* tp_methods */
	IPA_PKCS11_members, /* tp_members */
	0, /* tp_getset */
	0, /* tp_base */
	0, /* tp_dict */
	0, /* tp_descr_get */
	0, /* tp_descr_set */
	0, /* tp_dictoffset */
	(initproc)IPA_PKCS11_init, /* tp_init */
	0, /* tp_alloc */
	IPA_PKCS11_new, /* tp_new */
};

static PyMethodDef module_methods[] = { { NULL } /* Sentinel */
};

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC initipa_pkcs11(void) {
	PyObject* m;

	if (PyType_Ready(&IPA_PKCS11Type) < 0)
		return;

	/*
	 * Setting up ipa_pkcs11 module
	 */
	m = Py_InitModule3("ipa_pkcs11", module_methods,
			"Example module that creates an extension type.");

	if (m == NULL)
		return;

	/*
	 * Setting up IPA_PKCS11
	 */
	Py_INCREF(&IPA_PKCS11Type);
	PyModule_AddObject(m, "IPA_PKCS11", (PyObject *) &IPA_PKCS11Type);

	/*
	 * Setting up IPA_PKCS11 Exceptions
	 */
	IPA_PKCS11Error = PyErr_NewException("IPA_PKCS11.error", NULL, NULL);
	Py_INCREF(IPA_PKCS11Error);
	PyModule_AddObject(m, "error", IPA_PKCS11Error);

	IPA_PKCS11NotFound = PyErr_NewException("IPA_PKCS11.NotFound", NULL, NULL);
	Py_INCREF(IPA_PKCS11NotFound);
	PyModule_AddObject(m, "NotFound", IPA_PKCS11NotFound);

	IPA_PKCS11DuplicationError = PyErr_NewException("IPA_PKCS11.DuplicationError", NULL, NULL);
	Py_INCREF(IPA_PKCS11DuplicationError);
	PyModule_AddObject(m, "DuplicationError", IPA_PKCS11DuplicationError);

	/**
	 * Setting up module attributes
	 */
	PyObject *IPA_PKCS11_CLASS_PUBKEY_obj = PyInt_FromLong(CKO_PUBLIC_KEY);
	PyObject_SetAttrString(m, "KEY_CLASS_PUBLIC_KEY", IPA_PKCS11_CLASS_PUBKEY_obj);
	Py_XDECREF(IPA_PKCS11_CLASS_PUBKEY_obj);

	PyObject *IPA_PKCS11_CLASS_PRIVKEY_obj = PyInt_FromLong(CKO_PRIVATE_KEY);
	PyObject_SetAttrString(m, "KEY_CLASS_PRIVATE_KEY", IPA_PKCS11_CLASS_PRIVKEY_obj);
	Py_XDECREF(IPA_PKCS11_CLASS_PRIVKEY_obj);

	PyObject *IPA_PKCS11_CLASS_SECRETKEY_obj = PyInt_FromLong(CKO_SECRET_KEY);
	PyObject_SetAttrString(m, "KEY_CLASS_SECRET_KEY", IPA_PKCS11_CLASS_SECRETKEY_obj);
	Py_XDECREF(IPA_PKCS11_CLASS_SECRETKEY_obj);

}
