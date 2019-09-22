package zzc.jwt.commons;

import io.jsonwebtoken.Claims;

/**
 * �������
 *
 */
public class JWTResult {

	/**
	 * ������롣��JWTUtils�ж���ĳ���
	 */
	private int errCode;

	/**
	 * �Ƿ�ɹ�����������״̬
	 */
	private boolean success;

	/**
	 * ��֤������payload�е�����
	 */
	private Claims claims;

	public int getErrCode() {
		return errCode;
	}

	public void setErrCode(int errCode) {
		this.errCode = errCode;
	}

	public boolean isSuccess() {
		return success;
	}

	public void setSuccess(boolean success) {
		this.success = success;
	}

	public Claims getClaims() {
		return claims;
	}

	public void setClaims(Claims claims) {
		this.claims = claims;
	}

}
