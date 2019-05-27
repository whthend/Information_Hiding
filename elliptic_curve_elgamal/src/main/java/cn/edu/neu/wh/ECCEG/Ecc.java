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
  public static ArrayList<Pair<Point, Point>> encrypt(int[] bytes, Point publicKey) {
    ArrayList<Pair<Point, Point>> points = new ArrayList<Pair<Point, Point>>(bytes.length);
    for(int c : bytes) {
      //int c = b + 128;
      Point p = new Point(Constant.fa[c], Constant.fb[c]);
      points.add(p.encrypt(publicKey));
    }
    return points;
  }
  
  public static int[] decrypt(ArrayList<Pair<Point, Point>> cipher, int secretKey) {
    int[] bytes = new int[cipher.size()];
    int pt = 0;
    for(Pair<Point, Point> p : cipher) {
      Point plain = Point.decrypt(p, secretKey);
      bytes[pt++] = (int) (plain.x / Constant.k);
    }
    return bytes;
  }
}
