// -----BEGIN DISCLAIMER-----
/*******************************************************************************
 * Copyright (c) 2010 JCrypTool team and contributors
 *
 * All rights reserved. This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************/
// -----END DISCLAIMER-----
package org.jcryptool.visual.sha3candidates.algorithms;

/**
 *
 * @author Felix Tenne
 */

public class ECHOHashState {
    public byte tab[][][][];
    public byte tab_backup[][][][];
    public byte k1[][];
    public byte k2[][];
    public short index;
    public short bit_index;
    public short hashbitlen;
    public short cv_size;
    public short message_size;
    public short messlenhi;
    public short messlenlo;
    public short counter_hi;
    public short counter_lo;
    public short rounds;
    public short computed;

    private final short Addresses[][] = { {0, 0, 0, 0}, {0, 0, 1, 0}, {0, 0, 2, 0}, {0, 0, 3, 0}, {0, 0, 0, 1},
            {0, 0, 1, 1}, {0, 0, 2, 1}, {0, 0, 3, 1}, {0, 0, 0, 2}, {0, 0, 1, 2}, {0, 0, 2, 2}, {0, 0, 3, 2},
            {0, 0, 0, 3}, {0, 0, 1, 3}, {0, 0, 2, 3}, {0, 0, 3, 3}, {1, 0, 0, 0}, {1, 0, 1, 0}, {1, 0, 2, 0},
            {1, 0, 3, 0}, {1, 0, 0, 1}, {1, 0, 1, 1}, {1, 0, 2, 1}, {1, 0, 3, 1}, {1, 0, 0, 2}, {1, 0, 1, 2},
            {1, 0, 2, 2}, {1, 0, 3, 2}, {1, 0, 0, 3}, {1, 0, 1, 3}, {1, 0, 2, 3}, {1, 0, 3, 3}, {2, 0, 0, 0},
            {2, 0, 1, 0}, {2, 0, 2, 0}, {2, 0, 3, 0}, {2, 0, 0, 1}, {2, 0, 1, 1}, {2, 0, 2, 1}, {2, 0, 3, 1},
            {2, 0, 0, 2}, {2, 0, 1, 2}, {2, 0, 2, 2}, {2, 0, 3, 2}, {2, 0, 0, 3}, {2, 0, 1, 3}, {2, 0, 2, 3},
            {2, 0, 3, 3}, {3, 0, 0, 0}, {3, 0, 1, 0}, {3, 0, 2, 0}, {3, 0, 3, 0}, {3, 0, 0, 1}, {3, 0, 1, 1},
            {3, 0, 2, 1}, {3, 0, 3, 1}, {3, 0, 0, 2}, {3, 0, 1, 2}, {3, 0, 2, 2}, {3, 0, 3, 2}, {3, 0, 0, 3},
            {3, 0, 1, 3}, {3, 0, 2, 3}, {3, 0, 3, 3}, {0, 1, 0, 0}, {0, 1, 1, 0}, {0, 1, 2, 0}, {0, 1, 3, 0},
            {0, 1, 0, 1}, {0, 1, 1, 1}, {0, 1, 2, 1}, {0, 1, 3, 1}, {0, 1, 0, 2}, {0, 1, 1, 2}, {0, 1, 2, 2},
            {0, 1, 3, 2}, {0, 1, 0, 3}, {0, 1, 1, 3}, {0, 1, 2, 3}, {0, 1, 3, 3}, {1, 1, 0, 0}, {1, 1, 1, 0},
            {1, 1, 2, 0}, {1, 1, 3, 0}, {1, 1, 0, 1}, {1, 1, 1, 1}, {1, 1, 2, 1}, {1, 1, 3, 1}, {1, 1, 0, 2},
            {1, 1, 1, 2}, {1, 1, 2, 2}, {1, 1, 3, 2}, {1, 1, 0, 3}, {1, 1, 1, 3}, {1, 1, 2, 3}, {1, 1, 3, 3},
            {2, 1, 0, 0}, {2, 1, 1, 0}, {2, 1, 2, 0}, {2, 1, 3, 0}, {2, 1, 0, 1}, {2, 1, 1, 1}, {2, 1, 2, 1},
            {2, 1, 3, 1}, {2, 1, 0, 2}, {2, 1, 1, 2}, {2, 1, 2, 2}, {2, 1, 3, 2}, {2, 1, 0, 3}, {2, 1, 1, 3},
            {2, 1, 2, 3}, {2, 1, 3, 3}, {3, 1, 0, 0}, {3, 1, 1, 0}, {3, 1, 2, 0}, {3, 1, 3, 0}, {3, 1, 0, 1},
            {3, 1, 1, 1}, {3, 1, 2, 1}, {3, 1, 3, 1}, {3, 1, 0, 2}, {3, 1, 1, 2}, {3, 1, 2, 2}, {3, 1, 3, 2},
            {3, 1, 0, 3}, {3, 1, 1, 3}, {3, 1, 2, 3}, {3, 1, 3, 3}, {0, 2, 0, 0}, {0, 2, 1, 0}, {0, 2, 2, 0},
            {0, 2, 3, 0}, {0, 2, 0, 1}, {0, 2, 1, 1}, {0, 2, 2, 1}, {0, 2, 3, 1}, {0, 2, 0, 2}, {0, 2, 1, 2},
            {0, 2, 2, 2}, {0, 2, 3, 2}, {0, 2, 0, 3}, {0, 2, 1, 3}, {0, 2, 2, 3}, {0, 2, 3, 3}, {1, 2, 0, 0},
            {1, 2, 1, 0}, {1, 2, 2, 0}, {1, 2, 3, 0}, {1, 2, 0, 1}, {1, 2, 1, 1}, {1, 2, 2, 1}, {1, 2, 3, 1},
            {1, 2, 0, 2}, {1, 2, 1, 2}, {1, 2, 2, 2}, {1, 2, 3, 2}, {1, 2, 0, 3}, {1, 2, 1, 3}, {1, 2, 2, 3},
            {1, 2, 3, 3}, {2, 2, 0, 0}, {2, 2, 1, 0}, {2, 2, 2, 0}, {2, 2, 3, 0}, {2, 2, 0, 1}, {2, 2, 1, 1},
            {2, 2, 2, 1}, {2, 2, 3, 1}, {2, 2, 0, 2}, {2, 2, 1, 2}, {2, 2, 2, 2}, {2, 2, 3, 2}, {2, 2, 0, 3},
            {2, 2, 1, 3}, {2, 2, 2, 3}, {2, 2, 3, 3}, {3, 2, 0, 0}, {3, 2, 1, 0}, {3, 2, 2, 0}, {3, 2, 3, 0},
            {3, 2, 0, 1}, {3, 2, 1, 1}, {3, 2, 2, 1}, {3, 2, 3, 1}, {3, 2, 0, 2}, {3, 2, 1, 2}, {3, 2, 2, 2},
            {3, 2, 3, 2}, {3, 2, 0, 3}, {3, 2, 1, 3}, {3, 2, 2, 3}, {3, 2, 3, 3}, {0, 3, 0, 0}, {0, 3, 1, 0},
            {0, 3, 2, 0}, {0, 3, 3, 0}, {0, 3, 0, 1}, {0, 3, 1, 1}, {0, 3, 2, 1}, {0, 3, 3, 1}, {0, 3, 0, 2},
            {0, 3, 1, 2}, {0, 3, 2, 2}, {0, 3, 3, 2}, {0, 3, 0, 3}, {0, 3, 1, 3}, {0, 3, 2, 3}, {0, 3, 3, 3},
            {1, 3, 0, 0}, {1, 3, 1, 0}, {1, 3, 2, 0}, {1, 3, 3, 0}, {1, 3, 0, 1}, {1, 3, 1, 1}, {1, 3, 2, 1},
            {1, 3, 3, 1}, {1, 3, 0, 2}, {1, 3, 1, 2}, {1, 3, 2, 2}, {1, 3, 3, 2}, {1, 3, 0, 3}, {1, 3, 1, 3},
            {1, 3, 2, 3}, {1, 3, 3, 3}, {2, 3, 0, 0}, {2, 3, 1, 0}, {2, 3, 2, 0}, {2, 3, 3, 0}, {2, 3, 0, 1},
            {2, 3, 1, 1}, {2, 3, 2, 1}, {2, 3, 3, 1}, {2, 3, 0, 2}, {2, 3, 1, 2}, {2, 3, 2, 2}, {2, 3, 3, 2},
            {2, 3, 0, 3}, {2, 3, 1, 3}, {2, 3, 2, 3}, {2, 3, 3, 3}, {3, 3, 0, 0}, {3, 3, 1, 0}, {3, 3, 2, 0},
            {3, 3, 3, 0}, {3, 3, 0, 1}, {3, 3, 1, 1}, {3, 3, 2, 1}, {3, 3, 3, 1}, {3, 3, 0, 2}, {3, 3, 1, 2},
            {3, 3, 2, 2}, {3, 3, 3, 2}, {3, 3, 0, 3}, {3, 3, 1, 3}, {3, 3, 2, 3}, {3, 3, 3, 3}};

    public short[] getAddress(int address) {
        return Addresses[address];
    }

    ECHOHashState() {
        this.tab = new byte[4][4][4][4];
        this.tab_backup = new byte[4][4][4][4];
        this.k1 = new byte[4][4];
        this.k2 = new byte[4][4];
    }
}
