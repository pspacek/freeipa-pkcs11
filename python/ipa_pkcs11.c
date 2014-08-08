#include <Python.h>
#include "structmember.h"

#include <pkcs11.h>

#include "library.h"

// compat
#define CKM_AES_KEY_WRAP           (0x1090)

CK_BBOOL true = CK_TRUE;
CK_BBOOL false = CK_FALSE;

/**
 * IPA_PKCS11 Exception
 */
static PyObject *IPA_PKCS11Error;

/*
 * Support functions
 */

/**
 * Tests result value of pkc11 operations
 * Returns 1 if everything is ok
 * Returns 0 if error occurs and set the error message
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

/**
 * IPA_PKCS11 object
 */
typedef struct {
	PyObject_HEAD
	CK_SLOT_ID slot;
	CK_FUNCTION_LIST_PTR p11;
	CK_SESSION_HANDLE session;
} IPA_PKCS11;

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

static PyMethodDef IPA_PKCS11_methods[] = {
		{ "initialize",
		(PyCFunction) IPA_PKCS11_initialize, METH_VARARGS,
		"Inicialize pkcs11 library" },
		{ "finalize",
		(PyCFunction) IPA_PKCS11_finalize, METH_NOARGS,
		"Finalize operations with pkcs11 library" },
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
	 * Setting up IPA_PKCS11 Exception (IPA_PKCS11.error)
	 */
	IPA_PKCS11Error = PyErr_NewException("IPA_PKCS11.error", NULL, NULL);
	Py_INCREF(IPA_PKCS11Error);
	PyModule_AddObject(m, "error", IPA_PKCS11Error);
}
