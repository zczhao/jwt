package zzc.jwt.commons;

/**
 * ��ΪSubject����ʹ�ã�Ҳ����payload�б����public claims�� ���в������κ��������ݣ� �����н���ʹ��ʵ������
 */
public class JWTSubject {

	private String username;

	public JWTSubject() {
		super();
	}

	public JWTSubject(String username) {
		super();
		this.username = username;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

}
