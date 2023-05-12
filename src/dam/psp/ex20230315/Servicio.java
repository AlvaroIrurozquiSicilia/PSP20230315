package dam.psp.ex20230315;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Servicio implements Runnable {
	Socket sCliente;
	String[] arrayPeticion;

	public Servicio(Socket socket) {
		this.sCliente = socket;
	}

	@Override
	public void run() {
		try {
			DataInputStream in = new DataInputStream(sCliente.getInputStream());
			String opcion = in.readUTF();
			SwitchPeticiones(opcion, in);
		} catch (EOFException e) {
			enviarRespuesta("ERROR:Se esperaba una petición");
		} catch (SocketTimeoutException e) {
			enviarRespuesta("ERROR:Read timed out");
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				sCliente.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private void SwitchPeticiones(String token, DataInputStream in) {
		System.out.println("Peticion de " + sCliente.getRemoteSocketAddress() + ": " + token);
		switch (token) {
		case "hash":
			secuenciaBytes(in);
			break;
		case "cert":
			almacenarCertificado(in);
			break;
		case "cifrar":
			cifrar(in);
			break;
		default:
			enviarRespuesta("ERROR:'" + token + "' no se reconoce como una petición válida");
		}
	}

	void secuenciaBytes(DataInputStream in) {
		try {
			MessageDigest md;
			String algoritmo = in.readUTF();
			md = MessageDigest.getInstance(algoritmo);
			byte[] bytes = in.readAllBytes();
			if (bytes.length > 0) {
				String cadena = Base64.getEncoder().encodeToString(md.digest(bytes));
				enviarRespuesta("OK:" + cadena);
			} else
				enviarRespuesta("ERROR:Se esperaban datos");
		} catch (SocketTimeoutException e) {
			enviarRespuesta("ERROR:Read timed out");
		} catch (EOFException e) {
			enviarRespuesta("ERROR:Se esperaba un algoritmo");
		} catch (IOException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	void almacenarCertificado(DataInputStream in) {
		String alias;
		try {
			alias = in.readUTF();
			try {
				String base = in.readUTF();
				CertificateFactory f = CertificateFactory.getInstance("X.509");
				byte[] byteEncoded = Base64.getDecoder().decode(base);
				Certificate cert = f.generateCertificate(new ByteArrayInputStream(byteEncoded));
				Servidor.ks.setCertificateEntry(alias, cert);
				MessageDigest md;
				md = MessageDigest.getInstance("SHA-256");
				md.update(base.getBytes());
				String cadena = Base64.getEncoder().encodeToString(md.digest());
				enviarRespuesta("OK:" + cadena);
			} catch (CertificateException e) {
			} catch (IllegalArgumentException e) {
				enviarRespuesta("ERROR:Se esperaba Base64");
			} catch (EOFException e) {
				enviarRespuesta("ERROR:Se esperaba un certificado");
			} catch (SocketTimeoutException e) {
				enviarRespuesta("ERROR:Read timed out");
			}
		} catch (EOFException e) {
			enviarRespuesta("ERROR:Se esperaba un alias");
		} catch (SocketTimeoutException e) {
			enviarRespuesta("ERROR:Read timed out");
		} catch (IOException e) {
		} catch (KeyStoreException e) {
		} catch (NoSuchAlgorithmException e) {
		}
	}

	void cifrar(DataInputStream in) {
		String alias = null;
		int contador = 0;
		try {
			alias = in.readUTF();
			Certificate cert = Servidor.ks.getCertificate(alias);
			if (cert == null)
				enviarRespuesta("ERROR:'" + alias + "' no es un certificado");
			else {
				Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				c.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
				int n;
				byte[] bloque = new byte[256];
				DataOutputStream out = new DataOutputStream(sCliente.getOutputStream());
				try{
					while ((n = in.read(bloque)) != -1) {
						contador++;
						byte[] cifrado = c.doFinal(bloque, 0, n);
						out.writeUTF("OK:" + Base64.getEncoder().encodeToString(cifrado));
					}
					if(contador == 0) {
						enviarRespuesta("ERROR:Se esperaban datos");
					}
				}catch(SocketTimeoutException e) {
					enviarRespuesta("ERROR:Read timed out");
				}
					

			}

		} catch (SocketTimeoutException e) {
			enviarRespuesta("ERROR:Read timed out");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (EOFException e) {
			enviarRespuesta("ERROR:Se esperaba un alias");
		} catch (IOException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			enviarRespuesta("ERROR:'"+ alias + "' no contiene una clave RSA");
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	}

	void guardarPrivada(PrivateKey key, String nombreFichero) {
		File file = new File("res/" + nombreFichero);
		try (DataOutputStream out = new DataOutputStream(new FileOutputStream(file))) {
			out.writeUTF(key.getAlgorithm());
			out.write(key.getEncoded());
			enviarRespuesta("OK:bloque_cifrado_codificado_en_base64");
		} catch (SocketTimeoutException e) {
			enviarRespuesta("ERROR:Read timed out");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	void enviarRespuesta(String respuesta) {
		try {
			new DataOutputStream(sCliente.getOutputStream()).writeUTF(respuesta);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}