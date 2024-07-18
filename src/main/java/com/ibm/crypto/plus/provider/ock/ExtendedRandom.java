/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider.ock;

import com.ibm.crypto.plus.provider.CleanableObject;
import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;

public final class ExtendedRandom implements CleanableObject {

    OCKContext ockContext;
    long ockPRNGContextId;

    public static ExtendedRandom getInstance(OCKContext ockContext, String algName)
            throws OCKException {
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if ((algName == null) || algName.isEmpty()) {
            throw new IllegalArgumentException("algName is null/empty");
        }

        return new ExtendedRandom(ockContext, algName);
    }

    private ExtendedRandom(OCKContext ockContext, String algName) throws OCKException {
        this.ockContext = ockContext;
        this.ockPRNGContextId = NativeInterface.EXTRAND_create(ockContext.getId(), algName);

        OpenJCEPlusProvider.registerCleanable(this);
    }

    public synchronized void nextBytes(byte[] bytes) throws OCKException {
        if (bytes == null) {
            throw new IllegalArgumentException("bytes is null");
        }

        if (bytes.length > 0) {
            NativeInterface.EXTRAND_nextBytes(ockContext.getId(), ockPRNGContextId, bytes);
        }
    }

    public synchronized void setSeed(byte[] seed) throws OCKException {
        if (seed == null) {
            throw new IllegalArgumentException("seed is null");
        }

        if (seed.length > 0) {
            NativeInterface.EXTRAND_setSeed(ockContext.getId(), ockPRNGContextId, seed);
        }
    }

    @Override
    public synchronized void cleanup() {
        if (ockPRNGContextId != 0) {
            try {
                NativeInterface.EXTRAND_delete(ockContext.getId(), ockPRNGContextId);
            } catch (OCKException e) {
                e.printStackTrace();
            }
            ockPRNGContextId = 0;
        }
    }
}
