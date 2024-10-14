from django.urls import path
from .views import *

urlpatterns = [
    path('register/', RegistrationView.as_view(), name='register'),
    path('referral-link/',ReferralLinkView.as_view(),name='referral_link'),
    path('referred-users/', ReferredUsersView.as_view(), name='referred-users'),
    path('verify-email/<str:token>/', VerifyEmailView.as_view(), name='verify-email'),
    path('login/',LoginView.as_view(),name='login'),
    path('forgot/',ForgotPasswordView.as_view(),name='forgot_password'),
    path('reset-password/<str:token>/',PasswordResetView.as_view(),name='reset_password'),
    path('logout/',LogoutView.as_view(),name='logout'),
    path('details/<int:id>/',UserDetailView.as_view(),name='details'),
    path('update/',UserDetailView.as_view(),name='update')
]