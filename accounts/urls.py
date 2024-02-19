from django.conf.urls import url
from . import views
urlpatterns = [
    url(r'^login/$', views.custom_login, name='login'),
    url(r'^logout/$', views.custom_logout, name='logout'),
    url(r'^signup/$', views.signup, name='signup'),
    url(r'^password/$', views.change_password, name='change_password'),
    url('dashboard/', views.dashboard),
    url('activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/',views.activate, name='activate'),
    url('activate1/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/',views.activate1, name='activate1'),
    url(r'^reset/$', views.reset, name='reset')
]
