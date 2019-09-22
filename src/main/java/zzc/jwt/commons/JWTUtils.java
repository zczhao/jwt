package zzc.jwt.commons;

import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;

/**
 * JWT������
 *
 */
public class JWTUtils {

	/**
	 * ��������key���������ӽ��ܵ�key���� ���������ʹ�ÿͻ������ɵ�kye����ǰ����ĳ������Բ�ʹ��
	 */
	private static final String JWT_SECERT = "test_jwt_secert";
	private static final ObjectMapper MAPPER = new ObjectMapper();
	private static final int JWT_ERRCODE_EXPIRE = 1005;// Token����
	private static final int JWT_ERRCODE_FAIL = 1006;// ��֤��ͨ��

	public static SecretKey generalkey() {
		try {
			// byte[] encodedkey = Base64.decode(JWT_SECERT);
			// ������һ�ַ�ʽj���յõ�һ��byte[]���͵�key����
			byte[] encodedkey = JWT_SECERT.getBytes("UTF-8");
			SecretKey key = new SecretKeySpec(encodedkey, 0, encodedkey.length, "AES");
			return key;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * ǩ��JWT������token�ķ���
	 * 
	 * @param id        JWT��Ψһ��ݱ�ʶ����Ҫ������Ϊһ����token,�Ӷ��ر��ع���
	 * @param iss       JWTǩ����
	 * @param subject   JWT��������û���payload�м�¼��public claims����ǰ�����о����û��ĵ�¼��
	 * @param ttlMillis ��Ч�ڣ���λ����
	 * @return token token��һ���Եģ���Ϊһ���û�����Ч��¼����׼����һ��token���û��˳���ʱ��tokenʧЧ
	 */
	public static String createJWT(String id, String iss, String subject, long ttlMillis) {
		// �����㷨
		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
		// ��ǰʱ��
		long nowMillis = System.currentTimeMillis();
		// ��ǰʱ������ڶ���
		Date now = new Date(nowMillis);
		SecretKey secretKey = generalkey();
		// ����JWT�Ĺ�����������ʹ��ָ������Ϣ�ͼ����㷨����token�Ĺ���
		JwtBuilder builder = Jwts.builder()
				.setId(id) // ������ݱ�־������һ���ͻ���Ψһ��ǡ��磺����ʹ�û����������ͻ��˵�IP,�ͻ������ɵ��������
				.setIssuer(iss)
				.setSubject(subject)
				.setIssuedAt(now) // token���ɵ�ʱ��
				.signWith(signatureAlgorithm, secretKey); // �趨�ܳ׺��㷨
		if(ttlMillis >= 0) {
			long expMillis = nowMillis + ttlMillis;
			Date expDate = new Date(expMillis); // token��ʧЧʱ��
			builder.setExpiration(expDate);
		}
		return builder.compact(); // ����token
	}

	/**
	 * ��֤JWT
	 * @param jwtStr
	 * @return
	 */
	public static JWTResult validateJWT(String jwtStr) {
		JWTResult checkResult = new JWTResult();
		Claims claims = null;
		try {
			claims = parseJWT(jwtStr);
			checkResult.setSuccess(true);
			checkResult.setClaims(claims);
		} catch (ExpiredJwtException e) {
			checkResult.setErrCode(JWT_ERRCODE_EXPIRE);
			checkResult.setSuccess(false);
		} catch (SignatureException e) {
			checkResult.setErrCode(JWT_ERRCODE_FAIL);
			checkResult.setSuccess(false);
		} catch (Exception e) {
			checkResult.setErrCode(JWT_ERRCODE_FAIL);
			checkResult.setSuccess(false);
		}
		return checkResult;
	}

	/**
	 * ����JWT�ַ���
	 * @param jwtStr ���Ƿ�����Ϊ�ͻ������ɵ�ǩ�����ݣ�����token
	 * @return
	 */
	private static Claims parseJWT(String jwtStr) throws Exception{
		SecretKey secretKey = generalkey();
		return Jwts.parser()
				.setSigningKey(secretKey)
				.parseClaimsJws(jwtStr)
				.getBody();// getBody��ȡ�ľ���token�м�¼��payload���ݡ�����payload�б�������е�claims
	}
	
	/**
	 * ����subject��Ϣ
	 * @param subObj - Ҫת���Ķ���
	 * @return Java����->JSON�ַ�������ʱ����null
	 */
	public static String generalSubject(Object subObj) {
		try {
			return MAPPER.writeValueAsString(subObj);
		} catch (JsonProcessingException e) {
			e.printStackTrace();
			return null;
		}
	}
}
