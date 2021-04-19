from django.urls import path
from dashboard import views
app_name = 'dashboard'
urlpatterns = [ 
    path('create', views.dashboard_index ,name="index"),
    path('libraries', views.dashboard_libraries ,name="libraries"),
    path('lib_scan/<int:lib_id>', views.library_scan , name="lib_scan"),
    path('vuln_check/<int:lib_id>', views.vuln_check , name="vuln_check"),
    path('delete_librabry/<int:librabry_id>', views.delete_librabry , name="delete_librabry"),
    path('cve_scan', views.cve_scan , name="cve_scan"),


    
 
]