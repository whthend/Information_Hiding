package cn.edu.neu.wh.ECCEG;

import java.util.ArrayList;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author Luqman A. Siswanto
 */
public class Ecc {
  public Ecc() {
    
  }
  public static Pair<Point, Point> encrypt(int bytes, Point publicKey) {
//    ArrayList<Pair<Point, Point>> points = new ArrayList<Pair<Point, Point>>(bytes.length);
//    for(int c : bytes) {
      //int c = b + 128;
      Point p = new Point(Constant.fa[bytes], Constant.fb[bytes]);
      Pair encryptPari = p.encrypt(publicKey);
//      points.add(p.encrypt(publicKey));
//    }
    return encryptPari;
  }
  
  public static int decrypt(Pair<Point, Point> cipher, int secretKey) {
    int bytes;
//    int pt = 0;
//    for(Pair<Point, Point> p : cipher) {
      Point plain = Point.decrypt(cipher, secretKey);
      bytes = (int) (plain.x / Constant.k);

    return bytes;
  }

  public int[][] encodeMod(long massege[][], int modnumber){
    int[][] modMassege = new int[massege.length][massege[0].length];
    int row_num = massege.length;
    int column_num = massege[0].length;

    for (int i = 0; i < row_num; i++){
      for(int j = 0; j < column_num; j++){
        modMassege[i][j] = (int) massege[i][j] % modnumber;
      }
    }
    return modMassege;
  }

  public Pair<Point, Point> cipher_add(Pair<Point, Point> cipher1, Pair<Point, Point> cipher2) {
    Point first = cipher1.first.add(cipher2.first);
    Point second = cipher1.second.add(cipher2.second);

    return new Pair(first, second);
  }

  public Pair<Point, Point> cipher_sub(Pair<Point, Point> cipher1, Pair<Point, Point> cipher2) {
    Point first = cipher1.first.subtract(cipher2.first);
    Point second = cipher1.second.subtract(cipher2.second);

    return new Pair(first, second);
  }



}
