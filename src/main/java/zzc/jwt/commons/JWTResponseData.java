package zzc.jwt.commons;

/**
 * ���ظ��ͻ��˵Ķ���
 */
public class JWTResponseData {

	private Integer code; // �����룬����HTTP��Ӧ��
	private Object data;// ҵ������
	private String msg;// ��������
	private String token;// ��ݱ�ʶ��JWT���ɵ�����

	public Integer getCode() {
		return code;
	}

	public void setCode(Integer code) {
		this.code = code;
	}

	public Object getData() {
		return data;
	}

	public void setData(Object data) {
		this.data = data;
	}

	public String getMsg() {
		return msg;
	}

	public void setMsg(String msg) {
		this.msg = msg;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

}
