package com.fsck.k9.crypto.blockcipher;


import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;


public class RoundKey {
    private BigInteger externalKey;
    private List<List<Integer>> matrixRoundKey;
    private List<Long> listRoundKey = new ArrayList<>();
    private static final int N = 16;
    private static final int MOD = 251;

    public RoundKey(BigInteger externalKey){
        assert (externalKey.compareTo(new BigInteger("0")) >= 0);
        this.externalKey = externalKey;
        this.matrixRoundKey = MatrixRoundKey.getMatrix();
    }

    public void copyMatrix(List<List<Integer>> src,List<List<Integer>> dest){
        for(int i=0;i<N;i++){
            for(int j=0;j<N;j++){
                dest.get(i).set(j,src.get(i).get(j));
            }
        }
    }

    public List<List<Integer>> mul(List<List<Integer>>mat1, List<List<Integer>>mat2){
        int row = mat1.size();
        int col = mat2.get(0).size();
        List<List<Integer>> res = new ArrayList<>();
        for(int i=0;i<row;i++){
            res.add(new ArrayList<>());
            for(int j=0;j<col;j++){
                int tmp = 0;
                for(int k=0;k<mat2.size();k++){
                    tmp += mat1.get(i).get(k) * mat2.get(k).get(j);
                    tmp %= MOD;
                }
                res.get(i).add(tmp);
            }
        }
        return res;
    }

    public List<List<Integer>> initMat(List<List<Integer>>mat,int row,int col){
        List<List<Integer>>res = new ArrayList<>();
        for(int i=0;i<row;i++){
            res.add(new ArrayList<>());
            for(int j=0;j<col;j++){
                res.get(i).add(0);
            }
        }
        return res;
    }

    public List<List<Integer>> matPow(List<List<Integer>>mat, long n){
        if(n == 1){
            return initMat(mat,mat.size(),mat.get(0).size());
        }
        List<List<Integer>>newMat = matPow(mat,n/2);
        if(n % 2 == 1){
            return mul(newMat,mat);
        }else{
            return newMat;
        }
    }

    public List<Integer> splitTo8Bit(long l,long r){
        List<Integer>res = new ArrayList<>();
        for(int i=0;i<8;i++){
            long x = r % (1<<8);
            r >>= 8;
            res.add((int)x);
        }
        for(int i=0;i<8;i++){
            long x = l % (1<<8);
            l >>= 8;
            res.add((int)x);
        }
        // reverse
        for(int i=0;i<16;i++){
            int tmp = res.get(i);
            res.set(i,res.get(15-i));
            res.set(15-i,tmp);
        }

        return res;
    }

    public long arithmeticRightShift(long x,int k){
        long mask = (1<<63);
        for(int i=0;i<k;i++){
            if(x % 2 == 1){
                x >>= 1;
                x |= mask;
            }else{
                x >>= 1;
            }
        }
        return x;
    }

    public int bitCount(long x){
        int res = 0;
        while(x > 0){
            if(x % 2 == 1){
                res++;
            }
            x >>= 1;
        }
        return res;
    }

    public List<Long> getListRoundKey(){
        if(this.listRoundKey.size() != 0){
            return this.listRoundKey;
        }
        List<Long>res = new ArrayList<>();

        long l = this.externalKey.shiftRight(64).longValue();
        long r = this.externalKey.mod(new BigInteger("1").shiftLeft(64)).longValue();

        for(int i=0;i<N;i++){
            long xor = l^r;

            // Power matrix by xor (mat**xor)
            List<List<Integer>>newMat = matPow(this.matrixRoundKey,xor);

            // Multiply matrix and l r splitted per 8 bit -> result list length 16 [[e1,e2,...]]
            List<List<Integer>>tempList = new ArrayList<>();
            tempList.add(splitTo8Bit(l,r));
            List<List<Integer>>listKey = mul(newMat,tempList);

            // Convert listKey to integer
            long keyL = 0;
            for(int j=0;j<8;j++){
                keyL += listKey.get(0).get(i);
                if(j == 7)break;
                keyL <<= 8;
            }
            long keyR = 0;
            for(int j=0;j<8;j++){
                keyR += listKey.get(0).get(i+8);
                if(j == 7)break;
                keyR <<= 8;
            }

            keyL = arithmeticRightShift(keyL,bitCount(keyL));
            keyR = arithmeticRightShift(keyR,bitCount(keyR));

            long key = keyL ^ keyR;

            res.add(key);

            // Swap l and r
            l = keyR;
            r = keyL;
        }
        for(int i=0;i<16;i++){
            this.listRoundKey.add(res.get(i));
        }

        return res;
    }
}
