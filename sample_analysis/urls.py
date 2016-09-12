from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.upload_form, name='index'),
    url(r'^$', views.upload_form, name='upload_page'),
    url(r'^sha256/(?P<sha256>[A-Fa-f0-9]{64})/$', views.display_report_by_sha256),
    url(r'^md5/(?P<md5>[A-Fa-f0-9]{32})/$', views.display_report_by_md5),
]
