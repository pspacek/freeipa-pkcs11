/*
 * Copyright (C) 2014  Red Hat
 * Author: Petr Spacek <pspacek@redhat.com>
 * Author: Martin Basti <mbasti@redhat.com>
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
create_replica_key_pair(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
     CK_RV rv;
     CK_OBJECT_HANDLE publicKey, privateKey;
     CK_MECHANISM mechanism = {
          CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
     };
     CK_ULONG modulusBits = 2048;
     CK_BYTE publicExponent[] = { 1, 0, 1 }; /* 65537 (RFC 6376 section 3.3.1)*/
     CK_BYTE subject[] = "replica1-keypair";
     CK_BYTE id[] = {'r'};
     CK_ATTRIBUTE publicKeyTemplate[] = {
          {CKA_ID, id, sizeof(id)},
          {CKA_LABEL, subject, sizeof(subject) - 1},
          {CKA_TOKEN, &true, sizeof(true)},
          {CKA_WRAP, &true, sizeof(true)},
          {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
          {CKA_PUBLIC_EXPONENT, publicExponent, 3},
     };
     CK_ATTRIBUTE privateKeyTemplate[] = {
          {CKA_ID, id, sizeof(id)},
          {CKA_LABEL, subject, sizeof(subject) - 1},
          {CKA_TOKEN, &true, sizeof(true)},
          {CKA_PRIVATE, &true, sizeof(true)},
          {CKA_SENSITIVE, &false, sizeof(false)}, // prevents wrapping
          {CKA_UNWRAP, &true, sizeof(true)},
          {CKA_EXTRACTABLE, &true, sizeof(true)},
          {CKA_WRAP_WITH_TRUSTED, &false, sizeof(false)} // prevents wrapping
     };

     rv = p11->C_GenerateKeyPair(session,
                            &mechanism,
                            publicKeyTemplate,
			    sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE),
                            privateKeyTemplate,
			    sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE),
                            &publicKey,
                            &privateKey);
     check_return_value(rv, "generate key pair");
     return CKR_OK;
}


CK_RV
do_something(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
	return create_replica_key_pair(p11, session);
}
