/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hsm.data.encryption;

import java.sql.Timestamp;
import java.util.Date;

/**
 *
 * @author danidu_o
 */
public class LogFileCreator {
     public static synchronized void writeInfoLogs(final String msg)
    {
        System.out.println(msg);
    }
     public static String getTime()
    {
        return new Timestamp(new Date().getTime()).toString();
    }
}
