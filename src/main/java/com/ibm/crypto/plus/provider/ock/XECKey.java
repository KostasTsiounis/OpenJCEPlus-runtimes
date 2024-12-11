/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider.ock;

import java.util.Arrays;

public final class XECKey implements AsymmetricKey {
    private OCKContext ockContext;
    private long xecKeyId;
    private byte[] privateKeyBytes;
    private byte[] publicKeyBytes;
    private static final String badIdMsg = "XEC Key Identifier is not valid";
    private static final int FastJNIBufferSize = 3000;

    // Buffer to pass XDH data from/to native efficiently
    private static final ThreadLocal<FastJNIBuffer> buffer = new ThreadLocal<FastJNIBuffer>() {
        @Override
        protected FastJNIBuffer initialValue() {
            return FastJNIBuffer.create(FastJNIBufferSize);
        }
    };

    private XECKey(OCKContext ockContext, long xecKeyId) {
        //final String methodName = "XECKey(long, byte[], byte[]) ";
        this.ockContext = ockContext;
        this.xecKeyId = xecKeyId;
    }


    public static XECKey generateKeyPair(OCKContext ockContext, int curveNum, int pub_size)
            throws OCKException {
        //final String methodName = "generateKeyPair(NamedParameterSpec.CURVE) ";
        if (ockContext == null) {
            throw new IllegalArgumentException("The context parameter is null");
        }
        long xecKeyId = NativeInterface.XECKEY_generate(ockContext.getId(), curveNum);
        if (!validId(xecKeyId)) {
            throw new OCKException(badIdMsg);
        }
        return new XECKey(ockContext, xecKeyId);
    }

    public static byte[] computeECDHSecret(OCKContext ockContext, long genCtx, long pubId,
            long privId, int secrectBufferSize) throws OCKException {
        if (ockContext == null)
            throw new IllegalArgumentException("context is null");
        if (pubId == 0)
            throw new IllegalArgumentException("The public key parameter is not valid");
        if (privId == 0)
            throw new IllegalArgumentException("The private key parameter is not valid");

        byte[] sharedSecretBytes = NativeInterface.XECKEY_computeECDHSecret(ockContext.getId(),
                genCtx, pubId, privId, secrectBufferSize);
        //OCKDebug.Msg (debPrefix, methodName,  "pubId :" + pubId + " privId :" + privId + " sharedSecretBytes :", sharedSecretBytes);
        return sharedSecretBytes;
    }

    protected static boolean validId(long id) {
        //final String methodName = "validId";
        //OCKDebug.Msg (debPrefix, methodName, "id :" + id);
        return (id != 0L);
    }

    private synchronized void obtainPrivateKeyBytes() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPrivateKeyBytes at the same time, we only want to call the
        // native code one time.
        //
        if (null == privateKeyBytes) {
            if (!validId(xecKeyId))
                throw new OCKException(badIdMsg);
            this.privateKeyBytes = NativeInterface.XECKEY_getPrivateKeyBytes(ockContext.getId(),
                    xecKeyId); // Returns DER encoded bytes
        }
    }

    @Override
    public byte[] getPrivateKeyBytes() throws OCKException {
        //final String methodName = "getPrivateKeyBytes()";
        if (null == privateKeyBytes) {
            obtainPrivateKeyBytes();
        }
        return (privateKeyBytes == null) ? null : privateKeyBytes.clone();
    }

    private synchronized void obtainPublicKeyBytes() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPrivateKeyBytes at the same time, we only want to call the
        // native code one time.
        //
        if (null == publicKeyBytes) {
            if (!validId(xecKeyId))
                throw new OCKException(badIdMsg);
            this.publicKeyBytes = NativeInterface.XECKEY_getPublicKeyBytes(ockContext.getId(),
                    xecKeyId); // Returns DER encoded bytes
        }
    }

    @Override
    public byte[] getPublicKeyBytes() throws OCKException {
        //final String methodName = "getPublickeyBytes()";
        if (null == publicKeyBytes) {
            obtainPublicKeyBytes();
        }
        return (publicKeyBytes == null) ? null : publicKeyBytes.clone();
    }

    @Override
    protected synchronized void finalize() throws Throwable {
        //final String methodName = "finalize ";
        //OCKDebug.Msg(debPrefix, methodName,  "ecKeyId :" + ecKeyId + " pkeyId=" + pkeyId);
        try {
            if (privateKeyBytes != null) {
                Arrays.fill(privateKeyBytes, (byte) 0x00);
            }

            if (xecKeyId != 0) {
                NativeInterface.XECKEY_delete(ockContext.getId(), xecKeyId);
                xecKeyId = 0;
            }
        } finally {
            super.finalize();
        }
    }

    public synchronized static XECKey createPrivateKey(OCKContext ockContext,
            byte[] privateKeyBytes, int priv_size) throws OCKException {
        //final String methodName = "createPrivateKey";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }
        if (privateKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }
        long xecKeyId = NativeInterface.XECKEY_createPrivateKey(ockContext.getId(), privateKeyBytes);
        if (!validId(xecKeyId)) {
            throw new OCKException(badIdMsg);
        }
        return new XECKey(ockContext, xecKeyId);
    }

    public static XECKey createPublicKey(OCKContext ockContext, byte[] publicKeyBytes)
            throws OCKException {
        //final String methodName = "createPublicKey";
        if (ockContext == null)
            throw new IllegalArgumentException("context is null");
        if (publicKeyBytes == null)
            throw new IllegalArgumentException("key bytes is null");

        long xecKeyId = NativeInterface.XECKEY_createPublicKey(ockContext.getId(), publicKeyBytes);
        if (!validId(xecKeyId)) {
            throw new OCKException(badIdMsg);
        }
        return new XECKey(ockContext, xecKeyId);
    }

    public String getAlgorithm() {
        return "XDH";
    }

    @Override
    public long getPKeyId() throws OCKException {
        return xecKeyId;
    }
}
