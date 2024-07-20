import io 
import base64
from django.shortcuts import render, redirect
from django.http import JsonResponse
from .forms import DocumentForm
import aspose.pdf as pdf
import aspose.pydrawing as drawing
import datetime
from cryptography import x509

def prueba01(request):
    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():
            pdf_file = request.FILES['pdf']
            p12_file = request.FILES['p12']
            password = form.cleaned_data['password']
            
            # Leer el contenido del archivo PDF subido
            pdf_bytes = pdf_file.read()
            pdf_stream = io.BytesIO(pdf_bytes)
            
            # Leer el contenido del archivo P12 subido
            p12_bytes = p12_file.read()
            p12_stream = io.BytesIO(p12_bytes)
            print(pdf_file.name)
            print(p12_file.name)
            print(password)
            #################
            date = datetime.datetime.now()
            date = date.strftime("D:%Y%m%d%H%M%S+00'00'")
            dct = {
                "aligned": 0,
                "sigflags": 3,
                "sigflagsft": 132,
                "sigpage": 0,
                "sigbutton": True,
                "sigfield": "Signature1",
                "auto_sigfield": True,
                "sigandcertify": True,
                "signaturebox": (470, 840, 570, 640),
                "signature": "Aquí va la firma",
                # "signature_img": "signature_test.png",
                "contact": "hola@ejemplo.com",
                "location": "Ubicación",
                "signingdate": date,
                "reason": "Razón",
                "password": password,
            }
            # with open("cert.p12", "rb") as fp:
            p12 = pkcs12.load_key_and_certificates(
                p12_stream.read(), password.encode("ascii"), backends.default_backend()
            )

            #datau = open(fname, "rb").read()
            datau = pdf_stream.read()
            datas = cms.sign(datau, dct, p12[0], p12[1], p12[2], "sha256")
            archivo_pdf_para_enviar_al_cliente = io.BytesIO()
            archivo_pdf_para_enviar_al_cliente.write(datau)
            archivo_pdf_para_enviar_al_cliente.write(datas)
            archivo_pdf_para_enviar_al_cliente.seek(0)
            # Codificar el flujo de bytes en base64
            signed_pdf_base64 = base64.b64encode(archivo_pdf_para_enviar_al_cliente.read()).decode('utf-8')
            
            
            
            """LEEEEER INFOR"""
    
            private_key = p12[0]
            if private_key:
                private_key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
                print(private_key_pem.decode("utf-8"))

            # Extraer el certificado
            certificate = p12[1]
            if certificate:
                cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
                print(cert_pem.decode("utf-8"))

            # Extraer certificados de la cadena (si los hay)
            additional_certs = p12[2]
            for cert in additional_certs:
                cert_pem = cert.public_bytes(serialization.Encoding.PEM)
                print(cert_pem.decode("utf-8"))
            # Obtener el Subject
            #cert = x509.load_pem_x509_certificate(p12_bytes, default_backend())
            subject = cert.subject
            for attribute in subject:
                print(f"{attribute.oid._name}: {attribute.value}")

            return JsonResponse({'message': 'Archivo subido con éxito!', 'signed_pdf': signed_pdf_base64})
        else:
            return JsonResponse({'message': 'Error al subir el archivo'}, status=400)
    else:
        form = DocumentForm()
    return render(request, 'prueba01.html', {'form': form})



############ 19/07/2024

##############           PRUEBA 01
import io 
import base64
from django.shortcuts import render, redirect
from django.http import JsonResponse
from .forms import DocumentForm
import aspose.pdf as pdf
import aspose.pydrawing as drawing
import datetime
from cryptography import x509

def prueba01(request):
    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():
            pdf_file = request.FILES['pdf']
            p12_file = request.FILES['p12']
            password = form.cleaned_data['password']
            
            # Leer el contenido del archivo PDF subido
            pdf_bytes = pdf_file.read()
            pdf_stream = io.BytesIO(pdf_bytes)
            
            # Leer el contenido del archivo P12 subido
            p12_bytes = p12_file.read()
            p12_stream = io.BytesIO(p12_bytes)
            print(pdf_file.name)
            print(p12_file.name)
            print(password)
            #################
            date = datetime.datetime.now()
            date = date.strftime("D:%Y%m%d%H%M%S+00'00'")
            dct = {
                "aligned": 0,
                "sigflags": 3,
                "sigflagsft": 132,
                "sigpage": 0,
                "sigbutton": True,
                "sigfield": "Signature1",
                "auto_sigfield": True,
                "sigandcertify": True,
                "signaturebox": (470, 840, 570, 640),
                "signature": "Aquí va la firma",
                # "signature_img": "signature_test.png",
                "contact": "hola@ejemplo.com",
                "location": "Ubicación",
                "signingdate": date,
                "reason": "Razón",
                "password": password,
            }
            # with open("cert.p12", "rb") as fp:
            p12 = pkcs12.load_key_and_certificates(
                p12_stream.read(), password.encode("ascii"), backends.default_backend()
            )

            #datau = open(fname, "rb").read()
            datau = pdf_stream.read()
            datas = cms.sign(datau, dct, p12[0], p12[1], p12[2], "sha256")
            archivo_pdf_para_enviar_al_cliente = io.BytesIO()
            archivo_pdf_para_enviar_al_cliente.write(datau)
            archivo_pdf_para_enviar_al_cliente.write(datas)
            archivo_pdf_para_enviar_al_cliente.seek(0)
            # Codificar el flujo de bytes en base64
            signed_pdf_base64 = base64.b64encode(archivo_pdf_para_enviar_al_cliente.read()).decode('utf-8')
            
            
            
            """LEEEEER INFOR"""
    
            private_key = p12[0]
            if private_key:
                private_key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
                print(private_key_pem.decode("utf-8"))

            # Extraer el certificado
            certificate = p12[1]
            if certificate:
                cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
                print(cert_pem.decode("utf-8"))

            # Extraer certificados de la cadena (si los hay)
            additional_certs = p12[2]
            for cert in additional_certs:
                cert_pem = cert.public_bytes(serialization.Encoding.PEM)
                print(cert_pem.decode("utf-8"))
            # Obtener el Subject
            #cert = x509.load_pem_x509_certificate(p12_bytes, default_backend())
            # Cargar y procesar el archivo P12
            private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                p12_bytes, 
                password.encode(),  # Asegúrate de que la contraseña esté codificada en bytes
                default_backend()
            )
            
            # Obtener el sujeto del certificado
            subject = certificate.subject
            for attribute in subject:
                print(f"{attribute.oid._name}: {attribute.value}")

            return JsonResponse({'message': 'Archivo subido con éxito!', 'signed_pdf': signed_pdf_base64})
        else:
            return JsonResponse({'message': 'Error al subir el archivo'}, status=400)
    else:
        form = DocumentForm()
    return render(request, 'prueba01.html', {'form': form})
