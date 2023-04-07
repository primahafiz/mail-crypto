package com.fsck.k9.crypto.blockcipher;


import java.util.ArrayList;
import java.util.List;
import java.util.Random;


public class MatrixRoundKey {
    public static List<List<Integer>> matrix = new ArrayList<>();
    private static final int mxm = 251;

    public static List<List<Integer>> getMatrix(){
        if(matrix.size() != 0){
            return matrix;
        }
        Random rand = new Random();
        for(int i=0;i<16;i++){
            matrix.add(new ArrayList<>());
            for(int j=0;j<16;j++){
                matrix.get(i).add(rand.nextInt(mxm+1));
            }
        }
        return matrix;
    }
}
