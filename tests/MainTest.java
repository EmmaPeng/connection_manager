

import java.security.MessageDigest;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.BreakIterator;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.StringTokenizer;
import java.util.concurrent.ConcurrentHashMap;

/*
javac MainTest.java
java -cp . MainTest
*/

public class MainTest {
	
	public static String encodeHex(byte[] bytes) {
        StringBuilder buf = new StringBuilder(bytes.length * 2);
        int i;
        
        for (i = 0; i < bytes.length; i++) {
            if (((int)bytes[i] & 0xff) < 0x10) {
                buf.append("0");
            }
            buf.append(Long.toString((int)bytes[i] & 0xff, 16));
        }
        return buf.toString();
    }
	
	private static String byto2hex2(byte[] bin){
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < bin.length; ++i) {
			int x = bin[i] & 0xFF, h = x >>> 4, l = x & 0x0F;
			buf.append((char) (h + ((h < 10) ? '0' : 'a' - 10)));
			buf.append((char) (l + ((l < 10) ? '0' : 'a' - 10)));
		}
		return buf.toString();
	}

	public static void main(String[] args) throws Exception {

		String streamID = "4b1b474";
		String keys = "789";

		MessageDigest digest;
		digest = MessageDigest.getInstance("SHA-1");
		digest.update(streamID.getBytes());
		//digest.update(keys.getBytes());
		String key = StringUtils.encodeHex(digest.digest(keys.getBytes()));
		//String key = StringUtils.encodeHex(digest.digest());
		//String key = StringUtils.encodeHex(streamID.getBytes());
		//String key = new String(Base64.encode(digest.digest()));
		//key = byto2hex2(digest.digest());

		System.out.println(" streamid: \""+streamID+"\", encrypted: \""+key+"\", base64: "+StringUtils.encodeBase64(digest.digest()));


	}

}

class StringUtils {
    
    
    
    private static final char[] QUOTE_ENCODE = "&quot;".toCharArray();
    private static final char[] AMP_ENCODE = "&amp;".toCharArray();
    private static final char[] LT_ENCODE = "&lt;".toCharArray();
    private static final char[] GT_ENCODE = "&gt;".toCharArray();
    
    private StringUtils() {
        
    }
    
    public static String replace(String string, String oldString, String newString) {
        if (string == null) {
            return null;
        }
        int i = 0;
        
        if ((i = string.indexOf(oldString, i)) >= 0) {
            
            char[] string2 = string.toCharArray();
            char[] newString2 = newString.toCharArray();
            int oLength = oldString.length();
            StringBuilder buf = new StringBuilder(string2.length);
            buf.append(string2, 0, i).append(newString2);
            i += oLength;
            int j = i;
            
            while ((i = string.indexOf(oldString, i)) > 0) {
                buf.append(string2, j, i - j).append(newString2);
                i += oLength;
                j = i;
            }
            buf.append(string2, j, string2.length - j);
            return buf.toString();
        }
        return string;
    }
    
    public static String replaceIgnoreCase(String line, String oldString,
                                           String newString) {
        if (line == null) {
            return null;
        }
        String lcLine = line.toLowerCase();
        String lcOldString = oldString.toLowerCase();
        int i = 0;
        if ((i = lcLine.indexOf(lcOldString, i)) >= 0) {
            char[] line2 = line.toCharArray();
            char[] newString2 = newString.toCharArray();
            int oLength = oldString.length();
            StringBuilder buf = new StringBuilder(line2.length);
            buf.append(line2, 0, i).append(newString2);
            i += oLength;
            int j = i;
            while ((i = lcLine.indexOf(lcOldString, i)) > 0) {
                buf.append(line2, j, i - j).append(newString2);
                i += oLength;
                j = i;
            }
            buf.append(line2, j, line2.length - j);
            return buf.toString();
        }
        return line;
    }
    
    public static String replaceIgnoreCase(String line, String oldString,
                                           String newString, int[] count)
    {
        if (line == null) {
            return null;
        }
        String lcLine = line.toLowerCase();
        String lcOldString = oldString.toLowerCase();
        int i = 0;
        if ((i = lcLine.indexOf(lcOldString, i)) >= 0) {
            int counter = 1;
            char[] line2 = line.toCharArray();
            char[] newString2 = newString.toCharArray();
            int oLength = oldString.length();
            StringBuilder buf = new StringBuilder(line2.length);
            buf.append(line2, 0, i).append(newString2);
            i += oLength;
            int j = i;
            while ((i = lcLine.indexOf(lcOldString, i)) > 0) {
                counter++;
                buf.append(line2, j, i - j).append(newString2);
                i += oLength;
                j = i;
            }
            buf.append(line2, j, line2.length - j);
            count[0] = counter;
            return buf.toString();
        }
        return line;
    }
    
    public static String replace(String line, String oldString,
                                 String newString, int[] count)
    {
        if (line == null) {
            return null;
        }
        int i = 0;
        if ((i = line.indexOf(oldString, i)) >= 0) {
            int counter = 1;
            char[] line2 = line.toCharArray();
            char[] newString2 = newString.toCharArray();
            int oLength = oldString.length();
            StringBuilder buf = new StringBuilder(line2.length);
            buf.append(line2, 0, i).append(newString2);
            i += oLength;
            int j = i;
            while ((i = line.indexOf(oldString, i)) > 0) {
                counter++;
                buf.append(line2, j, i - j).append(newString2);
                i += oLength;
                j = i;
            }
            buf.append(line2, j, line2.length - j);
            count[0] = counter;
            return buf.toString();
        }
        return line;
    }
    
    public static String stripTags(String in) {
        if (in == null) {
            return null;
        }
        char ch;
        int i = 0;
        int last = 0;
        char[] input = in.toCharArray();
        int len = input.length;
        StringBuilder out = new StringBuilder((int)(len * 1.3));
        for (; i < len; i++) {
            ch = input[i];
            if (ch > '>') {
            }
            else if (ch == '<') {
                if (i + 3 < len && input[i + 1] == 'b' && input[i + 2] == 'r' && input[i + 3] == '>') {
                    i += 3;
                    continue;
                }
                if (i > last) {
                    out.append(input, last, i - last);
                }
                last = i + 1;
            }
            else if (ch == '>') {
                last = i + 1;
            }
        }
        if (last == 0) {
            return in;
        }
        if (i > last) {
            out.append(input, last, i - last);
        }
        return out.toString();
    }
    
    public static String escapeHTMLTags(String in) {
    	return escapeHTMLTags(in, true);
    }
    
    public static String escapeHTMLTags(String in, boolean includeLF) {
        if (in == null) {
            return null;
        }
        char ch;
        int i = 0;
        int last = 0;
        char[] input = in.toCharArray();
        int len = input.length;
        StringBuilder out = new StringBuilder((int)(len * 1.3));
        for (; i < len; i++) {
            ch = input[i];
            if (ch > '>') {
            }
            else if (ch == '<') {
                if (i > last) {
                    out.append(input, last, i - last);
                }
                last = i + 1;
                out.append(LT_ENCODE);
            }
            else if (ch == '>') {
                if (i > last) {
                    out.append(input, last, i - last);
                }
                last = i + 1;
                out.append(GT_ENCODE);
            }
            else if (ch == '\n' && includeLF == true) {
                if (i > last) {
                    out.append(input, last, i - last);
                }
                last = i + 1;
                out.append("<br>");
            }
        }
        if (last == 0) {
            return in;
        }
        if (i > last) {
            out.append(input, last, i - last);
        }
        return out.toString();
    }
    
    private static Map<String, MessageDigest> digests =
    new ConcurrentHashMap<String, MessageDigest>();
    
    public static String hash(String data) {
        return hash(data, "MD5");
    }
    
    public static String hash(String data, String algorithm) {
        try {
            return hash(data.getBytes("UTF-8"), algorithm);
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return data;
    }
    
    public static String hash(byte[] bytes, String algorithm) {
        synchronized (algorithm.intern()) {
            MessageDigest digest = digests.get(algorithm);
            if (digest == null) {
                try {
                    digest = MessageDigest.getInstance(algorithm);
                    digests.put(algorithm, digest);
                }
                catch (NoSuchAlgorithmException e) {
                     e.printStackTrace();
                    return null;
                }
            }
            
            digest.update(bytes);
            return encodeHex(digest.digest());
        }
    }
    
    public static String encodeHex(byte[] bytes) {
        StringBuilder buf = new StringBuilder(bytes.length * 2);
        int i;
        
        for (i = 0; i < bytes.length; i++) {
            if (((int)bytes[i] & 0xff) < 0x10) {
                buf.append("0");
            }
            buf.append(Long.toString((int)bytes[i] & 0xff, 16));
        }
        return buf.toString();
    }
    
    public static byte[] decodeHex(String hex) {
        char[] chars = hex.toCharArray();
        byte[] bytes = new byte[chars.length / 2];
        int byteCount = 0;
        for (int i = 0; i < chars.length; i += 2) {
            int newByte = 0x00;
            newByte |= hexCharToByte(chars[i]);
            newByte <<= 4;
            newByte |= hexCharToByte(chars[i + 1]);
            bytes[byteCount] = (byte)newByte;
            byteCount++;
        }
        return bytes;
    }
    
    private static byte hexCharToByte(char ch) {
        switch (ch) {
            case '0':
                return 0x00;
            case '1':
                return 0x01;
            case '2':
                return 0x02;
            case '3':
                return 0x03;
            case '4':
                return 0x04;
            case '5':
                return 0x05;
            case '6':
                return 0x06;
            case '7':
                return 0x07;
            case '8':
                return 0x08;
            case '9':
                return 0x09;
            case 'a':
                return 0x0A;
            case 'b':
                return 0x0B;
            case 'c':
                return 0x0C;
            case 'd':
                return 0x0D;
            case 'e':
                return 0x0E;
            case 'f':
                return 0x0F;
        }
        return 0x00;
    }
    
    public static String encodeBase64(String data) {
        byte[] bytes = null;
        try {
            bytes = data.getBytes("UTF-8");
        }
        catch (UnsupportedEncodingException uee) {
             uee.printStackTrace();
        }
        return encodeBase64(bytes);
    }
    
    public static String encodeBase64(byte[] b) {
        String s = null;
		if (b != null) {
			s = new sun.misc.BASE64Encoder().encode(b);
		}
		return s;
    }
    
    public static byte[] decodeBase64(String s) {
		byte[] b = null;
		if (s != null) {
			sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
			try {
				b = decoder.decodeBuffer(s);
				return b;
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return b;
    }
    
    public static String[] toLowerCaseWordArray(String text) {
        if (text == null || text.length() == 0) {
            return new String[0];
        }
        
        List<String> wordList = new ArrayList<String>();
        BreakIterator boundary = BreakIterator.getWordInstance();
        boundary.setText(text);
        int start = 0;
        
        for (int end = boundary.next(); end != BreakIterator.DONE;
             start = end, end = boundary.next()) {
            String tmp = text.substring(start, end).trim();
            
            tmp = replace(tmp, "+", "");
            tmp = replace(tmp, "/", "");
            tmp = replace(tmp, "\\", "");
            tmp = replace(tmp, "#", "");
            tmp = replace(tmp, "*", "");
            tmp = replace(tmp, ")", "");
            tmp = replace(tmp, "(", "");
            tmp = replace(tmp, "&", "");
            if (tmp.length() > 0) {
                wordList.add(tmp);
            }
        }
        return wordList.toArray(new String[wordList.size()]);
    }
    
    private static Random randGen = new Random();
    
    private static char[] numbersAndLetters = ("0123456789abcdefghijklmnopqrstuvwxyz" +
                                               "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ").toCharArray();
    
    public static String randomString(int length) {
        if (length < 1) {
            return null;
        }
        
        char[] randBuffer = new char[length];
        for (int i = 0; i < randBuffer.length; i++) {
            randBuffer[i] = numbersAndLetters[randGen.nextInt(71)];
        }
        return new String(randBuffer);
    }
    
    public static String chopAtWord(String string, int length) {
        if (string == null || string.length() == 0) {
            return string;
        }
        
        char[] charArray = string.toCharArray();
        int sLength = string.length();
        if (length < sLength) {
            sLength = length;
        }
        
        for (int i = 0; i < sLength - 1; i++) {
            
            if (charArray[i] == '\r' && charArray[i + 1] == '\n') {
                return string.substring(0, i + 1);
            }
            
            else if (charArray[i] == '\n') {
                return string.substring(0, i);
            }
        }
        
        if (charArray[sLength - 1] == '\n') {
            return string.substring(0, sLength - 1);
        }
        
        if (string.length() < length) {
            return string;
        }
        
        for (int i = length - 1; i > 0; i--) {
            if (charArray[i] == ' ') {
                return string.substring(0, i).trim();
            }
        }
        
        
        return string.substring(0, length);
    }
    
    public static String wordWrap(String input, int width, Locale locale) {
        
        if (input == null) {
            return "";
        }
        else if (width < 5) {
            return input;
        }
        else if (width >= input.length()) {
            return input;
        }
        
        
        StringBuilder buf = new StringBuilder(input);
        boolean endOfLine = false;
        int lineStart = 0;
        
        for (int i = 0; i < buf.length(); i++) {
            if (buf.charAt(i) == '\n') {
                lineStart = i + 1;
                endOfLine = true;
            }
            
            
            if (i > lineStart + width - 1) {
                if (!endOfLine) {
                    int limit = i - lineStart - 1;
                    BreakIterator breaks = BreakIterator.getLineInstance(locale);
                    breaks.setText(buf.substring(lineStart, i));
                    int end = breaks.last();
                    
                    if (end == limit + 1) {
                        if (!Character.isWhitespace(buf.charAt(lineStart + end))) {
                            end = breaks.preceding(end - 1);
                        }
                    }
                    
                    if (end != BreakIterator.DONE && end == limit + 1) {
                        buf.replace(lineStart + end, lineStart + end + 1, "\n");
                        lineStart = lineStart + end;
                    }
                    
                    else if (end != BreakIterator.DONE && end != 0) {
                        buf.insert(lineStart + end, '\n');
                        lineStart = lineStart + end + 1;
                    }
                    else {
                        buf.insert(i, '\n');
                        lineStart = i + 1;
                    }
                }
                else {
                    buf.insert(i, '\n');
                    lineStart = i + 1;
                    endOfLine = false;
                }
            }
        }
        
        return buf.toString();
    }
    
    public static String escapeForSQL(String string) {
        if (string == null) {
            return null;
        }
        else if (string.length() == 0) {
            return string;
        }
        
        char ch;
        char[] input = string.toCharArray();
        int i = 0;
        int last = 0;
        int len = input.length;
        StringBuilder out = null;
        for (; i < len; i++) {
            ch = input[i];
            
            if (ch == '\'') {
                if (out == null) {
                    out = new StringBuilder(len + 2);
                }
                if (i > last) {
                    out.append(input, last, i - last);
                }
                last = i + 1;
                out.append('\'').append('\'');
            }
        }
        
        if (out == null) {
            return string;
        }
        else if (i > last) {
            out.append(input, last, i - last);
        }
        
        return out.toString();
    }
    
    public static String escapeForXML(String string) {
        if (string == null) {
            return null;
        }
        char ch;
        int i = 0;
        int last = 0;
        char[] input = string.toCharArray();
        int len = input.length;
        StringBuilder out = new StringBuilder((int)(len * 1.3));
        for (; i < len; i++) {
            ch = input[i];
            if (ch > '>') {
            }
            else if (ch == '<') {
                if (i > last) {
                    out.append(input, last, i - last);
                }
                last = i + 1;
                out.append(LT_ENCODE);
            }
            else if (ch == '&') {
                if (i > last) {
                    out.append(input, last, i - last);
                }
                last = i + 1;
                out.append(AMP_ENCODE);
            }
            else if (ch == '"') {
                if (i > last) {
                    out.append(input, last, i - last);
                }
                last = i + 1;
                out.append(QUOTE_ENCODE);
            }
        }
        if (last == 0) {
            return string;
        }
        if (i > last) {
            out.append(input, last, i - last);
        }
        return out.toString();
    }
    
    public static String unescapeFromXML(String string) {
        string = replace(string, "&lt;", "<");
        string = replace(string, "&gt;", ">");
        string = replace(string, "&quot;", "\"");
        return replace(string, "&amp;", "&");
    }
    
    private static final char[] zeroArray =
    "0000000000000000000000000000000000000000000000000000000000000000".toCharArray();
    
    public static String zeroPadString(String string, int length) {
        if (string == null || string.length() > length) {
            return string;
        }
        StringBuilder buf = new StringBuilder(length);
        buf.append(zeroArray, 0, length - string.length()).append(string);
        return buf.toString();
    }
    
    public static String dateToMillis(Date date) {
        return zeroPadString(Long.toString(date.getTime()), 15);
    }
    
    public static String getTimeFromLong(long diff) {
        final String HOURS = "h";
        final String MINUTES = "min";
        
        
        final long MS_IN_A_DAY = 1000 * 60 * 60 * 24;
        final long MS_IN_AN_HOUR = 1000 * 60 * 60;
        final long MS_IN_A_MINUTE = 1000 * 60;
        final long MS_IN_A_SECOND = 1000;
        
        diff = diff % MS_IN_A_DAY;
        long numHours = diff / MS_IN_AN_HOUR;
        diff = diff % MS_IN_AN_HOUR;
        long numMinutes = diff / MS_IN_A_MINUTE;
        diff = diff % MS_IN_A_MINUTE;
        
        diff = diff % MS_IN_A_SECOND;
        
        StringBuffer buf = new StringBuffer();
        if (numHours > 0) {
            buf.append(numHours + " " + HOURS + ", ");
        }
        
        if (numMinutes > 0) {
            buf.append(numMinutes + " " + MINUTES);
        }
        
        
        String result = buf.toString();
        
        if (numMinutes < 1) {
            result = "< 1 minute";
        }
        
        return result;
    }
    
    public static String collectionToString(Collection<String> collection) {
        if (collection == null || collection.isEmpty()) {
            return "";
        }
        StringBuilder buf = new StringBuilder();
        String delim = "";
        for (String element : collection) {
            buf.append(delim);
            buf.append(element);
            delim = ",";
        }
        return buf.toString();
    }
    
    public static Collection<String> stringToCollection(String string) {
        if (string == null || string.trim().length() == 0) {
            return Collections.emptyList();
        }
        Collection<String> collection = new ArrayList<String>();
        StringTokenizer tokens = new StringTokenizer(string, ",");
        while (tokens.hasMoreTokens()) {
            collection.add(tokens.nextToken().trim());
        }
        return collection;
    }
    
    public static String abbreviate(String str, int maxWidth) {
        if (null == str) {
            return null;
        }
        
        if (str.length() <= maxWidth) {
            return str;
        }
        
        return str.substring(0, maxWidth) + "...";
    }
    
    
	public static String removeXSSCharacters(String input) {
		final String[] xss = { "<", ">", "\"", "'", "%", ";", ")", "(", "&",
            "+", "-" };
		for (int i = 0; i < xss.length; i++) {
			input = input.replace(xss[i], "");
		}
		return input;
	}
	/**
	 *
	 * 默认采用UTF-8，异常回滚使用系统默认编码，字节序列你逆向时需要注意！<br>
	 * add comment by buya
	 *
	 * @param input
	 * @return
	 */
	public static byte[] getBytes(String input) {
		try {
			return input.getBytes("UTF-8");
		} catch (UnsupportedEncodingException uee) {
			 uee.printStackTrace();
			return input.getBytes();  
		}
	}
	
	public static String getString(byte[] input) {
		try {
			return new String(input, "UTF-8");
		} catch (UnsupportedEncodingException uee) {
			String result = new String(input); 
			uee.printStackTrace();
			return result;
		}
	}
}
