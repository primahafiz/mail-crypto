package com.fsck.k9.crypto.blockcipher;


import java.util.ArrayList;
import java.util.List;


public class MatrixRoundKey {
    public static List<List<Integer>> matrix = new ArrayList<>();
    private static final int mxm = 251;

    private static int z = 11;
    private static int a = 131;
    private static int b = 23;

    public static List<List<Integer>> getMatrix(){
        if (matrix.size() != 0) {
            return matrix;
        }

        for(int i = 0; i < 16; i++){
            matrix.add(new ArrayList<>());
            for(int j = 0; j < 16; j++){
                z = (a * z + b) % mxm;
                matrix.get(i).add(z);
            }
        }
        return matrix;
    }
}
