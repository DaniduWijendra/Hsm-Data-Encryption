/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hsm.data.encryption;

import java.util.Scanner;

/**
 *
 * @author danidu_o
 */
public class HsmDataEncryption {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        String msg = "";
        String key = "";
        String length = "";
        String mode = "";
        String encData = "";
        String choice = "";
        String mac = "";
        String sha = "";
        String md = "";
        Scanner sc = new Scanner(System.in);
        System.out.println("=========================Check HSM STATUS =====================");
        try {
            if (HsmConnector.checkHsmStatus()) {
                System.out.println("Hsm connectivity and status is passed.[OK]");
            } else {
                System.out.println("Hsm connectivity and status is failed. [FAILED]");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("Enter the service you want: ");
        System.out.println("1 - Encrypt");
        System.out.println("2 - Decrypt");
        System.out.println("3 - MAC");
        System.out.println("4 - SHAGen");
        System.out.println("5 - MD5Gen");
        choice = sc.nextLine();
        switch (choice) {
            case "1":
                System.out.println("Enter the message you want to Encrypt: ");
                msg = sc.nextLine();
                System.out.println("Enter Key length: [1,2,3]");
                length = sc.nextLine();

                System.out.println("Enter the key you want: ");
                key = sc.nextLine();
                System.out.println("Ciper Mode ECB(00)/CBC(01) ");
                mode = sc.nextLine();
                try {
                    if (HsmConnector.keyValidate(length, key)) {
                        encData = HsmConnector.encryptMsg(msg, key, mode);
                        System.out.println("Encrypted Data: " + encData);

                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
            case "2":
                System.out.println("Enter the message you want to Decrypt: ");
                msg = sc.nextLine();
                System.out.println("Enter Key length: [1,2,3]");
                length = sc.nextLine();

                System.out.println("Enter the key you want: ");
                key = sc.nextLine();
                System.out.println("Ciper Mode ECB(00)/CBC(01) ");
                mode = sc.nextLine();
                try {
                    if (HsmConnector.keyValidate(length, key)) {
                        encData = HsmConnector.decryptMsg(msg, key, mode);
                        System.out.println("Encrypted Data: " + encData);

                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
            case "3":
                try
                {
                    mac = HsmConnector.macGen();
                    System.out.println("MAC: " + mac);
                }
                catch(Exception e)
                {
                    e.printStackTrace();
                }
                break;
            case "4":
                try
                {
                    sha = HsmConnector.shaGen();
                    System.out.println("SHA: " + sha);
                }
                catch(Exception e)
                {
                    e.printStackTrace();
                }
                break;
                case "5":
                try
                {
                    md = HsmConnector.md5Hash();
                    System.out.println("MD5: " + md);
                }
                catch(Exception e)
                {
                    e.printStackTrace();
                }
                break;
               
            default:
                System.out.println("Invalid choices");
        }

        

    }

}
