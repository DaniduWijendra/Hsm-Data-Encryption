/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hsm.data.encryption;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import org.jpos.iso.ISOUtil;

/**
 *
 * @author danidu_o
 */
public class HsmConnector {
    private static Socket socket;
    private static DataInputStream dataInputStream;
    private static DataOutputStream dataOutputStream;

    static {
        socket = null;
        dataInputStream = null;
        dataOutputStream = null;
    }

    public static boolean checkHsmStatus() throws Exception {
        boolean ok = false;
        try {
            socket = new Socket(InetAddress.getByName("192.168.20.216"), 8888);
            HsmConnector.dataOutputStream = new DataOutputStream(HsmConnector.socket.getOutputStream());
            HsmConnector.dataInputStream = new DataInputStream(HsmConnector.socket.getInputStream());
            final byte[] request = ISOUtil.hex2byte("010100000003FFF000");
            final byte[] response = new byte[1024];
            LogFileCreator.writeInfoLogs("\nRequest :\n" + ISOUtil.hexdump(request));
            HsmConnector.dataOutputStream.write(request);
            HsmConnector.dataOutputStream.flush();
            final int len = HsmConnector.dataInputStream.read(response, 0, 1024);
            LogFileCreator.writeInfoLogs("\nResponse: \n" + ISOUtil.hexdump(response));
            if (len > 5) {
                final String rc = ISOUtil.hexString(response).substring(16, 18);
                if (rc.equals("00")) {
                    ok = true;
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (HsmConnector.dataOutputStream != null) {
                HsmConnector.dataOutputStream.close();
            }
            if (HsmConnector.dataInputStream != null) {
                HsmConnector.dataInputStream.close();
            }
            if (HsmConnector.socket != null) {
                HsmConnector.socket.close();
            }
        }
        return ok;
    }
    public static boolean keyValidate(String length,String key)
    {
        boolean ok = false;
        if(length.trim().equals("1") && key.length() != 16)
        {
            System.out.println("Invalid key length 1...!!!");
        }
        else if(length.trim().equals("2") && key.length() != 32)
        {
            System.out.println("Invalid key length 2...!!!");
        }
        else if(length.trim().equals("3") && key.length() != 48)
        {
            System.out.println("Invalid key length 3...!!!");
        }
        else
        {
            ok = true;
        }
        return ok;
    }
    public String keySpec(String key)
    {
        String spec = "";
        switch (key.length()) {
            case 16:
                spec = "0910";
                break;
            case 32:
                spec = "1111";
                break;
            case 48:
                spec = "1912";
                break;
            default:
                break;
        }
        return spec;
    }
    public String msgSpec(String msg)
    {
        String spec = "";
        switch (msg.length()) {
            case 16:
                spec = "08";
                break;
            case 32:
                spec = "10";
                break;
            case 48:
                spec = "18";
                break;
            default:
                break;
        }
        return spec;
    }
    
    
    
    public static String encryptMsg(String msg,String key,String mode) throws Exception
    {
        String spec = "";
        String encData = "";
        String inputChain = "0000000000000000";
        HsmConnector sm = new HsmConnector();
        spec = sm.keySpec(key);
        try {
            
            (HsmConnector.socket = new Socket(InetAddress.getByName("192.168.20.216"), 8888)).setSoTimeout(10000);
            HsmConnector.dataOutputStream = new DataOutputStream(HsmConnector.socket.getOutputStream());
            HsmConnector.dataInputStream = new DataInputStream(HsmConnector.socket.getInputStream());
            byte[] request = null;
            request = ISOUtil.hex2byte("EE080000" + sm.keySpec(key) + key + mode + inputChain +sm.msgSpec(msg) + msg);
            System.out.println("Request " + ISOUtil.hexdump(request));
            final String hlen = Integer.toHexString(request.length);
            final String hd = "01010000" + ISOUtil.zeropad(hlen, 4);
            final byte[] response = new byte[1024];
            request = ISOUtil.concat(ISOUtil.hex2byte(hd), request);
            LogFileCreator.writeInfoLogs("\nRequest for Encrypted Data\n" + ISOUtil.hexdump(request));
            HsmConnector.dataOutputStream.write(request);
            HsmConnector.dataOutputStream.flush();
            final int reslen = HsmConnector.dataInputStream.read(response, 0, 1024);
            LogFileCreator.writeInfoLogs("\nResond for Encrypted Data\n" + ISOUtil.hexdump(response));
            if(reslen >= 10)
            {
                final String rc = ISOUtil.hexString(response).substring(18,20);
                if(rc.equals("00"))
                {
                    encData = ISOUtil.hexString(response).substring(38);
                    
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        finally {
            if (HsmConnector.dataInputStream != null) {
                HsmConnector.dataInputStream.close();
            }
            if (HsmConnector.dataOutputStream != null) {
                HsmConnector.dataOutputStream.close();
            }
            if (HsmConnector.socket != null) {
                HsmConnector.socket.close();
            }
        }
        
        return encData;
    }
    public static String decryptMsg(String msg,String key,String mode) throws Exception
    {
        String spec = "";
        String encData = "";
        String inputChain = "0000000000000000";
        HsmConnector sm = new HsmConnector();
        spec = sm.keySpec(key);
        try {
            
            (HsmConnector.socket = new Socket(InetAddress.getByName("192.168.20.216"), 8888)).setSoTimeout(10000);
            HsmConnector.dataOutputStream = new DataOutputStream(HsmConnector.socket.getOutputStream());
            HsmConnector.dataInputStream = new DataInputStream(HsmConnector.socket.getInputStream());
            byte[] request = null;
            request = ISOUtil.hex2byte("EE080100" + sm.keySpec(key) + key + mode + inputChain +sm.msgSpec(msg) + msg);
            System.out.println("Request " + ISOUtil.hexdump(request));
            final String hlen = Integer.toHexString(request.length);
            final String hd = "01010000" + ISOUtil.zeropad(hlen, 4);
            final byte[] response = new byte[1024];
            request = ISOUtil.concat(ISOUtil.hex2byte(hd), request);
            LogFileCreator.writeInfoLogs("\nRequest for Decrypted Data\n" + ISOUtil.hexdump(request));
            HsmConnector.dataOutputStream.write(request);
            HsmConnector.dataOutputStream.flush();
            final int reslen = HsmConnector.dataInputStream.read(response, 0, 1024);
            LogFileCreator.writeInfoLogs("\nResond for Decrypted Data\n" + ISOUtil.hexdump(response));
            if(reslen >= 10)
            {
                final String rc = ISOUtil.hexString(response).substring(18,20);
                if(rc.equals("00"))
                {
                    encData = ISOUtil.hexString(response).substring(38);
                    
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        finally {
            if (HsmConnector.dataInputStream != null) {
                HsmConnector.dataInputStream.close();
            }
            if (HsmConnector.dataOutputStream != null) {
                HsmConnector.dataOutputStream.close();
            }
            if (HsmConnector.socket != null) {
                HsmConnector.socket.close();
            }
        }
        
        return encData;
    }
    public static String macGen() throws Exception
    {
        String mac = "";
         try {
            
            (HsmConnector.socket = new Socket(InetAddress.getByName("192.168.20.216"), 8888)).setSoTimeout(10000);
            HsmConnector.dataOutputStream = new DataOutputStream(HsmConnector.socket.getOutputStream());
            HsmConnector.dataInputStream = new DataInputStream(HsmConnector.socket.getInputStream());
            byte[] request = null;
            request = ISOUtil.hex2byte("70" + "01" + "1234123412341234" + "1234123412341234");
            System.out.println("Request " + ISOUtil.hexdump(request));
            final String hlen = Integer.toHexString(request.length);
            final String hd = "01010000" + ISOUtil.zeropad(hlen, 4);
            final byte[] response = new byte[1024];
            request = ISOUtil.concat(ISOUtil.hex2byte(hd), request);
            LogFileCreator.writeInfoLogs("\nRequest for MAC Data\n" + ISOUtil.hexdump(request));
            HsmConnector.dataOutputStream.write(request);
            HsmConnector.dataOutputStream.flush();
            final int reslen = HsmConnector.dataInputStream.read(response, 0, 1024);
            LogFileCreator.writeInfoLogs("\nResond for MAC Data\n" + ISOUtil.hexdump(response));
            if(reslen >= 10)
            {
                final String rc = ISOUtil.hexString(response).substring(14,16);
                if(rc.equals("00"))
                {
                    mac = ISOUtil.hexString(response).substring(16,24);
                    
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        finally {
            if (HsmConnector.dataInputStream != null) {
                HsmConnector.dataInputStream.close();
            }
            if (HsmConnector.dataOutputStream != null) {
                HsmConnector.dataOutputStream.close();
            }
            if (HsmConnector.socket != null) {
                HsmConnector.socket.close();
            }
        }
        return mac;
    }
    public static String shaGen() throws Exception
    {
        String sha = "";
         try {
            
            (HsmConnector.socket = new Socket(InetAddress.getByName("192.168.20.216"), 8888)).setSoTimeout(10000);
            HsmConnector.dataOutputStream = new DataOutputStream(HsmConnector.socket.getOutputStream());
            HsmConnector.dataInputStream = new DataInputStream(HsmConnector.socket.getInputStream());
            byte[] request = null;
            request = ISOUtil.hex2byte("EE9008" + "00" + "0000" + "0000000000000000" + "14" +"0000000000000000000000000000000000000000" + "18" + "9CAAEF5CD4E554029CAAEF5CD4E554029CAAEF5CD4E55402");
            System.out.println("Request " + ISOUtil.hexdump(request));
            final String hlen = Integer.toHexString(request.length);
            final String hd = "01010000" + ISOUtil.zeropad(hlen, 4);
            final byte[] response = new byte[1024];
            request = ISOUtil.concat(ISOUtil.hex2byte(hd), request);
            LogFileCreator.writeInfoLogs("\nRequest for SHA Data\n" + ISOUtil.hexdump(request));
            HsmConnector.dataOutputStream.write(request);
            HsmConnector.dataOutputStream.flush();
            final int reslen = HsmConnector.dataInputStream.read(response, 0, 1024);
            LogFileCreator.writeInfoLogs("\nResond for SHA Data\n" + ISOUtil.hexdump(response));
            if(reslen >= 10)
            {
                final String rc = ISOUtil.hexString(response).substring(18,20);
                if(rc.equals("00"))
                {
                    sha = ISOUtil.hexString(response).substring(38,78);
                    
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        finally {
            if (HsmConnector.dataInputStream != null) {
                HsmConnector.dataInputStream.close();
            }
            if (HsmConnector.dataOutputStream != null) {
                HsmConnector.dataOutputStream.close();
            }
            if (HsmConnector.socket != null) {
                HsmConnector.socket.close();
            }
        }
        return sha;
    }
    public static String md5Hash() throws Exception
    {
        String md = "";
         try {
            
            (HsmConnector.socket = new Socket(InetAddress.getByName("192.168.20.216"), 8888)).setSoTimeout(10000);
            HsmConnector.dataOutputStream = new DataOutputStream(HsmConnector.socket.getOutputStream());
            HsmConnector.dataInputStream = new DataInputStream(HsmConnector.socket.getInputStream());
            byte[] request = null;
            request = ISOUtil.hex2byte("EE9007" + "00" + "00" + "0000000000000000" +"00000000000000000000000000000000" + "18" + "9CAAEF5CD4E554029CAAEF5CD4E554029CAAEF5CD4E55402");
            System.out.println("Request " + ISOUtil.hexdump(request));
            final String hlen = Integer.toHexString(request.length);
            final String hd = "01010000" + ISOUtil.zeropad(hlen, 4);
            final byte[] response = new byte[1024];
            request = ISOUtil.concat(ISOUtil.hex2byte(hd), request);
            LogFileCreator.writeInfoLogs("\nRequest for MD5 Data\n" + ISOUtil.hexdump(request));
            HsmConnector.dataOutputStream.write(request);
            HsmConnector.dataOutputStream.flush();
            final int reslen = HsmConnector.dataInputStream.read(response, 0, 1024);
            LogFileCreator.writeInfoLogs("\nResond for MD5 Data\n" + ISOUtil.hexdump(response));
            if(reslen >= 10)
            {
                final String rc = ISOUtil.hexString(response).substring(18,20);
                if(rc.equals("00"))
                {
                    md = ISOUtil.hexString(response).substring(36,68);
                    
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        finally {
            if (HsmConnector.dataInputStream != null) {
                HsmConnector.dataInputStream.close();
            }
            if (HsmConnector.dataOutputStream != null) {
                HsmConnector.dataOutputStream.close();
            }
            if (HsmConnector.socket != null) {
                HsmConnector.socket.close();
            }
        }
        return md;
    }
}
