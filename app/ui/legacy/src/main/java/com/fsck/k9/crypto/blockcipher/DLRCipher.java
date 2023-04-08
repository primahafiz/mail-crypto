package com.fsck.k9.crypto.blockcipher;


import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;


public class DLRCipher {

    private static final Character PADDING = '~';
    private static final int NROUND = 16;

    public static List<Integer>feistel(int a,int b,int c,int d,long key,int round){
        int resF1 = RoundFunction.calculate(a,key,round);
        int resF2 = RoundFunction.calculate(c,key,round);
        int resXor1 = b ^ resF1;
        int resXor2 = d ^ resF2;

        List<Integer>res = new ArrayList<>();
        res.add(a);
        res.add(resXor1);
        res.add(c);
        res.add(resXor2);

        return res;
    }

    public static String intToChar(int x){
        List<Integer>byteInt = new ArrayList<>();
        for(int i=0;i<4;i++){
            byteInt.add(x % (1<<8));
            x >>= 8;
        }
        String ans = "";
        for(int i=3;i>=0;i--){
            ans += (char)(int)byteInt.get(i);
        }
        return ans;
    }

    public static String calc(String text,String strExternalKey,Boolean isEncrypt){
        int countPadding = (16-text.length()%16)%16;
        for(int i=0;i<countPadding;i++){
            text += PADDING;
        }
        byte[] textBytes = text.getBytes();
        List<Integer>blocksQuarter = new ArrayList<>();
        for(int i=0;i<textBytes.length;i+=4){
            int block = 0;
            for(int j=0;j<4;j++){
                block += textBytes[i+j];
                if(j==3)break;
                block <<= 8;
            }
            blocksQuarter.add(block);
        }
        if(strExternalKey.length()<16){
            int countPaddingKey = 16-strExternalKey.length();
            for(int i=0;i<countPaddingKey;i++){
                strExternalKey += PADDING;
            }
        }
        BigInteger externalKey = new BigInteger("0");
        byte[] bytesExternalKey = strExternalKey.getBytes();
        for(int i=0;i<16;i++){
            externalKey.add(new BigInteger(String.valueOf(bytesExternalKey[i])));
            if(i==16)break;
            externalKey.shiftLeft(8);
        }
        RoundKey roundKey = new RoundKey(externalKey);
        List<Long>listRoundKey = roundKey.getListRoundKey();
        String ans = "";
        if(isEncrypt){
            for(int i=0;i<blocksQuarter.size();i+=4){
                List<Integer>cur = new ArrayList<>();
                for(int j=0;j<4;j++){
                    cur.add(blocksQuarter.get(i+j));
                }
                for(int j=0;j<NROUND;j++){
                    cur = feistel(cur.get(0),cur.get(1),cur.get(2),cur.get(3),listRoundKey.get(j),i+1);
                    List<Integer>tmpList = new ArrayList<>();
                    tmpList.add(cur.get(1));
                    tmpList.add(cur.get(2));
                    tmpList.add(cur.get(3));
                    tmpList.add(cur.get(0));
                    cur = tmpList;
                }
                for(int j=0;j<4;j++){
                    ans += intToChar(cur.get(i));
                }
            }
        }else{
            for(int i=0;i<blocksQuarter.size();i+=4){
                List<Integer>cur = new ArrayList<>();
                for(int j=0;j<4;j++){
                    cur.add(blocksQuarter.get(i+j));
                }
                for(int j=0;j<NROUND;j++){
                    cur = feistel(cur.get(0),cur.get(1),cur.get(2),cur.get(3),listRoundKey.get(j),i+1);
                    List<Integer>tmpList = new ArrayList<>();
                    tmpList.add(cur.get(3));
                    tmpList.add(cur.get(0));
                    tmpList.add(cur.get(1));
                    tmpList.add(cur.get(2));
                    cur = tmpList;
                }
                for(int j=0;j<4;j++){
                    ans += intToChar(cur.get(i));
                }
                int lstIdxPadding = ans.length();
                for(int j=ans.length()-1;j>=0;j--){
                    if(ans.charAt(j) != PADDING)break;
                    lstIdxPadding = j;
                }
                ans = ans.substring(0,lstIdxPadding);
            }
        }
        return ans;
    }

    public static String encrypt(String text,String strExternalKey){
        return calc(text,strExternalKey,true);
    }

    public static String decrypt(String text,String strExternalKey){
        return calc(text,strExternalKey,false);
    }
}
