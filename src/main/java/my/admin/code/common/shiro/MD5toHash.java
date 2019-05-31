package my.admin.code.common.shiro;


import org.apache.shiro.crypto.hash.Md5Hash;

public class MD5toHash {
    private String password;
    private String salt;
    private String hashpwd;
    private int hashcount;

    public MD5toHash(String password ) {
        this.password=password;


    }

    public MD5toHash(String password , String salt) {
        this.password=password;
        this.salt=salt;

    }

    public MD5toHash(String password , String salt, int hashcount) {
        this.password=password;
        this.salt=salt;
        this.hashcount=hashcount;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
    public String getSalt() {
        return salt;
    }
    public void setSalt(String salt) {
        this.salt = salt;
    }
    public String getHashpwd() {
        return hashpwd;
    }
    public void setHashpwd(String hashpwd) {
        this.hashpwd = hashpwd;
    }



    public int getHashcount() {
        return hashcount;
    }

    public void setHashcount(int hashcount) {
        this.hashcount = hashcount;
    }

    public String toMD5Hash() {
        String md5=null;
        if(getSalt()!=null && getHashcount()!=0) {
            md5 = new Md5Hash(this.getPassword(),this.getSalt(),this.getHashcount()).toString();
            System.out.println(md5);
        }
        else if(getSalt()!=null && getHashcount()==0) {
            md5 = new Md5Hash(this.getPassword(),this.getSalt()).toString();
            System.out.println(md5);
        }
        else if(getSalt()==null && getHashcount()==0) {
            md5 = new Md5Hash(this.getPassword()).toString();
            System.out.println(md5);
        }

        return md5;
    }
//	public static void main(String[] args) {
//		String md5=new MD5toHash("11","salt").toMD5Hash();
//	}

}
