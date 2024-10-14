from rest_framework import serializers
from .models import User
from django.contrib.auth.password_validation import validate_password

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'status'] 

class UserDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['id','username','phone_number','email','date_joined','avatar','referral_code','status']
        extra_kwargs = {
            'username': {'required': False},
            'email': {'required': False},
        }

class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password_confirm = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username','avatar','phone_number','email', 'password', 'password_confirm']

    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError("Passwords do not match.")
        return data
    
    def validate_password(self, value):
        user = User(username=self.initial_data.get('username'))
        validate_password(value, user=user) 
        return value

    def create(self, validated_data):
        validated_data.pop('password_confirm') 
        refer = self.context['request'].query_params.get('referral_code')
        user = User.objects.create_user(
        **validated_data, 
        )

        if refer:
            try:
                referrer = User.objects.get(referral_code=refer)
                user.referred_by = referrer  
                referrer.no_of_referrals += 1  
                referrer.save()
            except User.DoesNotExist:
                raise serializers.ValidationError({"referral_code": "Invalid referral code."})
        user.save()  
            
        return user
    
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email does not exist.")
        return value

class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(required=True,write_only=True)
    confirm_password=serializers.CharField(required=True,write_only=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

