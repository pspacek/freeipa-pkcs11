/*
 * Copyright (C) 2014  Red Hat
 * Author: Petr Spacek <pspacek@redhat.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * This code is based on PKCS#11 code snippets from NLnetLabs:
 * http://www.nlnetlabs.nl/publications/hsm/examples/pkcs11/
 * Original license follows:
 */

/*
 * Copyright (c) 2008, NLnet Labs
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *   - Neither the name of NLnet Labs nor the names of its contributors
 *     may be used to endorse or promote products derived from this
 *     software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "common.c"

CK_RV
export_secret_key(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
    CK_RV rv;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_BYTE id[] = {0x01};
    CK_ATTRIBUTE find_template[] = {
         { CKA_CLASS, &keyClass, sizeof(keyClass) },
         { CKA_ID, &id, sizeof(id) }
    };

    CK_ULONG objectCount;
    CK_OBJECT_HANDLE object;

    CK_BYTE_PTR value = NULL;
    unsigned int i;

    CK_ATTRIBUTE obj_template[] = {
         {CKA_VALUE, NULL_PTR, 0}
    };

    rv = p11->C_FindObjectsInit(session, find_template, 1);
    check_return_value(rv, "Find objects init");
    rv = p11->C_FindObjects(session, &object, 1, &objectCount);
    check_return_value(rv, "Find first object");

    if (objectCount != 1) {
	    rv = CKR_VENDOR_DEFINED;
	    check_return_value(rv, "Exactly 1 object is expected");
    }

    rv = p11->C_GetAttributeValue(session, object, obj_template, 1);
    check_return_value(rv, "get attribute value - prepare");
    
    /* Set proper size for attributes*/
    value = (CK_UTF8CHAR_PTR) malloc(obj_template[0].ulValueLen * sizeof(CK_BYTE));
    obj_template[0].pValue = value;
    
    rv = p11->C_GetAttributeValue(session, object, obj_template, 1);
    check_return_value(rv, "get attribute value");
    
    fprintf(stdout, "Found a key:\n");
    if (obj_template[0].ulValueLen > 0) {
         fprintf(stdout, "\tvalue: ");
         for(i=0; obj_template[0].ulValueLen>i; ++i) fprintf(stdout, "%02x", value[i]);
         fprintf(stdout, "\n");
         FILE *fp = get_key_file(p11, session, object);
         fwrite(obj_template[0].pValue, obj_template[0].ulValueLen, 1, fp);
    } else {
         fprintf(stderr, "\tvalue too large, or not found\n");
         return CKR_GENERAL_ERROR;
    }
       
    rv = p11->C_FindObjectsFinal(session);
    check_return_value(rv, "Find objects final");
    return CKR_OK;
}


CK_RV
do_something(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
	return export_secret_key(p11, session);
}
