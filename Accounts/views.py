from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated,IsAuthenticatedOrReadOnly
from django.core.mail import send_mail
from django.conf import settings
from .models import User
from rest_framework_simplejwt.exceptions import TokenError
from .serializers import *
from rest_framework_simplejwt.tokens import RefreshToken,AccessToken
# from rest_framework.renderers import (HTMLFormRenderer, JSONRenderer,BrowsableAPIRenderer,)
from rest_framework.pagination import PageNumberPagination
import logging

logger = logging.getLogger(__name__)

class CustomPagination(PageNumberPagination):
    page_size = 2
    page_size_query_param = 'page_size'
    max_page_size = 100

class ReferralLinkView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        referral_link = request.user.generate_referral_link()
        return Response({'referral_link': str(referral_link)},status=status.HTTP_200_OK)
    
class ReferredUsersView(APIView):
    permission_classes = [IsAuthenticated]  
    pagination_class = CustomPagination
    def get(self, request):
        user = request.user
        referred_users = User.objects.filter(referred_by=user) 
        paginator = self.pagination_class()
        paginated_users = paginator.paginate_queryset(referred_users, request)
        serializer = UserSerializer(paginated_users, many=True)
        return paginator.get_paginated_response(serializer.data)

class RegistrationView(APIView):
    serializer_class = RegistrationSerializer
    # renderer_classes = (BrowsableAPIRenderer, JSONRenderer, HTMLFormRenderer)

    def post(self, request):
        serializer = RegistrationSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = serializer.save()
            tokens = user.tokens()  

            return Response({
                "message": "User registered successfully! Please verify your email.",
                "access": tokens['access'],
                "refresh": tokens['refresh']
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyEmailView(APIView):
    def get(self, request, token):
        try:
            payload = AccessToken(token)
            user = User.objects.get(id=payload['user_id'])
            user.is_verified = True
            if user.referred_by:
                user.status='verified'
            user.save()

            return Response({"message": "Email verified successfully!"}, status=status.HTTP_200_OK)
        except (User.DoesNotExist):
            return Response({"error": "Invalid token or user."}, status=status.HTTP_400_BAD_REQUEST)
        
class LoginView(APIView):
    serializer_class = LoginSerializer
    def post(self,request,*args,**kwargs):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']

            try:
                user = User.objects.get(email=email) 
            except User.DoesNotExist:
                return Response({'error': 'Invalid email credentials'}, status=status.HTTP_401_UNAUTHORIZED)
            
            if user.check_password(password):  
                if user.is_verified:
                    refresh = RefreshToken.for_user(user)
                    return Response({
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                    })
                else:
                    return Response({'error': 'You are not verified. Please verify your email'}, status=status.HTTP_403_FORBIDDEN)
            else:
                logger.error("Error occurred : invalid credentials")
                return Response({'error': 'Invalid password credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Successfully logged out"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class ForgotPasswordView(APIView):
    serializer_class = ForgotPasswordSerializer
    # renderer_classes = (BrowsableAPIRenderer, JSONRenderer, HTMLFormRenderer)

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
                token = AccessToken.for_user(user)  
                reset_link = f"http://localhost:8000/api/reset-password/{token}"  

                send_mail(
                    subject='Password Reset Request',
                    message=f'Please use the following link to reset your password: {reset_link}',
                    from_email=settings.EMAIL_HOST_USER,
                    recipient_list=[user.email],
                    fail_silently=False,
                )

                return Response({"message": "Password reset link has been sent to your email."}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({"message": "If an account with this email exists, a password reset link has been sent."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class PasswordResetView(APIView):
    serializer_class = ResetPasswordSerializer
    # renderer_classes = (BrowsableAPIRenderer, JSONRenderer, HTMLFormRenderer)

    def post(self,request,token):
        try:
            payload = AccessToken(token)
            user = User.objects.get(id=payload['user_id'])

            serializer = ResetPasswordSerializer(data=request.data)
            if serializer.is_valid():
                data = serializer.validated_data
                new_password=data['new_password']
                user.set_password(new_password)
                user.save()
                return Response({'success':'Password updated successfully'},status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except (User.DoesNotExist):
            return Response({"error": "Invalid token or user."}, status=status.HTTP_400_BAD_REQUEST)
        except TokenError:
            return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
        
class UserDetailView(APIView):
    permission_classes=[IsAuthenticatedOrReadOnly]
    def get(self,request,id):
        try:
            user=User.objects.get(pk=id)
            serializer=UserDetailSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error':'user with the given id doesnot exists'},status=status.HTTP_404_NOT_FOUND)

    def put(self,request):
        try:
            user=request.user
            serializer=UserDetailSerializer(user,data=request.data)

            if serializer.is_valid():
                old_email = user.email
                new_email = serializer.validated_data.get('email')
                if new_email and new_email != old_email:
                    user.is_verified=False
                serializer.save()
                if new_email:
                    tokens = user.tokens()  
                    registration_view = RegistrationView()
                    registration_view.send_verification_email(user, tokens['access'])

                    return Response({
                          "message": "User registered successfully! Please verify your email.",
                          "access": tokens['access'],
                          "refresh": tokens['refresh'],
                          "message2":serializer.data
                          }, status=status.HTTP_201_CREATED)
                    
                return Response(serializer.data,status=status.HTTP_200_OK)
            return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'error':'user with the given id doesnot exists'},status=status.HTTP_404_NOT_FOUND)