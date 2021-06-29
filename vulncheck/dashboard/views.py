from django.shortcuts import render
import calendar
from datetime import datetime
from django.contrib.auth.decorators import login_required , permission_required
from pypi_simple import PyPISimple 
from dashboard.forms import Library_Form , CVE_Scan_Form
from dashboard.models import  Library
from django.contrib import messages
from django.utils import timezone
from django.urls import reverse
from django.http import HttpResponseRedirect
import vulners  
from django.core.mail import send_mail


# @login_required
# def dashboard_index(request):

    
    
#     url = "dashboard/index.html"    
#     with PyPISimple() as client:
#         requests_page = client.get_project_page('requests')
#     requests_page = client.get_project_page('requests')
#     pkg = requests_page.packages[0]
#     print(pkg.version)
    
#     context = {
#         'title': pkg.version,
       
        
      
#     }

#     return render(request , url , context) 

@login_required
def dashboard_index(request):
    form = None
    url = "dashboard/index.html" 
    if request.method == 'POST':
        form = Library_Form(request.POST, request.FILES)
        if(form.is_valid()):
            data = form.save(commit=False)
            data.created_at = timezone.now()
            data.updated_at = timezone.now()
            data.created_by = request.user.id
            data.save()
            messages.add_message(request, messages.INFO, 'Application Libraries stored successful')
            return HttpResponseRedirect(reverse('dashboard:libraries'))
     
    else:
        form = Library_Form()
    
    context = {
        
        'title': "Add Libraries",
        'form':form
        
    } 
     
    return render(request , url , context)

@login_required
def dashboard_libraries(request):
    libraries = Library.objects.all().order_by('-id')
    url = "dashboard/list_librabries.html" 
    # send_mail(
    #     'Payment',
    #     'find payment.',
    #     'kidkudzy@gmail.com',
    #     ['kmakufa@outlook.com', 'promiseksystems@gmail.com'],
    #     fail_silently=False,
    # )
    context = {
        
        'title': "Add Libraries",
        'libraries':libraries
        
    } 


    return render(request , url , context)



@login_required
def library_scan(request ,lib_id=None):
    library = Library.objects.filter(id=lib_id).order_by('-id')
    f = open(library[0].library_list.path, "r")
    print("------------------")

    lines = f.readlines()
    for line in lines:
        print(line)
    print("------------------")
    f.close()
    context = {
        "item":library[0], 
        "lines":lines
    }
    return render(request, 'dashboard/library_view.html', context)
    
@login_required
def scan_all(request ):

    url_path = "dashboard/scan_all.html"

    library = Library.objects.filter(data_mode="application").order_by('-id').first()
    print(library.data_mode)
    f = open(library.library_list.path, "r")
    print("------------------")
    lines = f.readlines()



    data = []
    Issues = []
    Affected_Cve = []


    for line in lines:
        # here comes the vuln scanner logic
        sep = '=='
        stripped = line.split(sep, 1)[0]
        lib_version = line.split(sep, 1)[1]
        is_safe = False
        
        # print(line.strip())
        # print("-------without end-------")
        # print(line.split(sep, 1)[0])
        # print("------with end-----")
        
        # check updates and security
        with PyPISimple() as client:
            requests_page = client.get_project_page(stripped.strip())
        
        requests_page = client.get_project_page(stripped.strip())
        pkg_params = {}

        if(library.data_mode == 'application'):
            

            try:
                try:
                    vulners_api = vulners.Vulners(api_key="4QIYDKA0NXPHUWXJNQYLISIZEZZH8FM25YNK0L518VOWJJEOWO81XGMH2KSL81KJ")
                    results = vulners_api.softwareVulnerabilities(stripped.strip(), lib_version.strip())
                    # print(len(stripped.strip()))
                    # print(len(lib_version.strip()))
                    # results = vulners_api.softwareVulnerabilities("httpd", "1.3")
                    exploit_list = results.get('exploit')
                    vulnerabilities_list = [results.get(key) for key in results if key not in ['info', 'blog', 'bugbounty']]
                    print("vulneralibity type_____"+vulnerabilities_list[0][0]['type'])
                    print(vulnerabilities_list[0][0]['title'])
                    Issues = vulnerabilities_list[0][0]
                    

                except:
                    is_safe = True
                    print("safe")
                pkg = requests_page.packages[0]
                pkg_params = {"name":pkg.project , "current_version":lib_version.strip() , "latest_version":pkg.version ,"digest":pkg.get_digests()['sha256'] , 'url':pkg.url ,'is_signed':pkg.has_sig ,'is_safe':is_safe ,'issue_title':Issues}
            except:
                pkg_params = {"name":stripped.strip() , "current_version":lib_version.strip() , "latest_version":"n/a" ,"digest":"n/a",'is_safe':is_safe ,'issue_title':Issues}

             # scan safety-db
            
        data.append(pkg_params.copy())
        # print(data)



    # application level 
    # 
    # 
    # 
    # 
    # 
    # 


    library = Library.objects.filter(data_mode="windows").order_by('-id').first()
    print(library.data_mode)
    f = open(library.library_list.path, "r")
    print("------------------")
    lines = f.readlines()



    windows = []
    Issues = []
    Affected_Cve = []
    

    for line in lines:
        # here comes the vuln scanner logic
        sep = '=='
        stripped = line.split(sep, 1)[0]
        lib_version = line.split(sep, 1)[1]
        is_safe = False
        
        # print(line.strip())
        # print("-------without end-------")
        # print(line.split(sep, 1)[0])
        # print("------with end-----")
        
        # check updates and security
        with PyPISimple() as client:
            requests_page = client.get_project_page(stripped.strip())
        
        requests_page = client.get_project_page(stripped.strip())
        windows_pkg_params = {}

        if(library.data_mode == 'windows'):
        

            try:
                vulners_api = vulners.Vulners(api_key="4QIYDKA0NXPHUWXJNQYLISIZEZZH8FM25YNK0L518VOWJJEOWO81XGMH2KSL81KJ")
                win_vulners = vulners_api.kbAudit(os="Windows Server 2012 R2", kb_list=[lib_version.strip()])
                need_2_install_kb = win_vulners['kbMissed']
                affected_cve = win_vulners['cvelist']
                print("_____affected cve_____")
                print(affected_cve[0])
                Affected_Cve = affected_cve

            except:
                is_safe = True
                
            windows_pkg_params = {"name":stripped.strip() , "kb_name":lib_version.strip() , "latest_version":"n/a" ,"digest":"n/a",'is_safe':is_safe ,'affected_cve':Affected_Cve}
            #  scan safety-db
            
        windows.append(windows_pkg_params.copy())
        # print(data)


    # f = open(library[0].library_list.path, "r")
    # print("------------------")

    # lines = f.readlines()

    # data = []
    # Issues = []
    # Affected_Cve = []
    # url_path = ""
   
    # for line in lines:
    #     # here comes the vuln scanner logic
    #     sep = '=='
    #     stripped = line.split(sep, 1)[0]
    #     lib_version = line.split(sep, 1)[1]
    #     is_safe = False
        
    #     # print(line.strip())
    #     # print("-------without end-------")
    #     # print(line.split(sep, 1)[0])
    #     # print("------with end-----")
      
    #     # check updates and security
    #     with PyPISimple() as client:
    #         requests_page = client.get_project_page(stripped.strip())
        
    #     requests_page = client.get_project_page(stripped.strip())
    #     pkg_params = {}

    #     if(library[0].data_mode == 'application'):
    #         url_path = "dashboard/app_vulncheck.html"

    #         try:
    #             try:
    #                 vulners_api = vulners.Vulners(api_key="4QIYDKA0NXPHUWXJNQYLISIZEZZH8FM25YNK0L518VOWJJEOWO81XGMH2KSL81KJ")
    #                 results = vulners_api.softwareVulnerabilities(stripped.strip(), lib_version.strip())
    #                 # print(len(stripped.strip()))
    #                 # print(len(lib_version.strip()))
    #                 # results = vulners_api.softwareVulnerabilities("httpd", "1.3")
    #                 exploit_list = results.get('exploit')
    #                 vulnerabilities_list = [results.get(key) for key in results if key not in ['info', 'blog', 'bugbounty']]
    #                 print("vulneralibity type_____"+vulnerabilities_list[0][0]['type'])
    #                 print(vulnerabilities_list[0][0]['title'])
    #                 Issues = vulnerabilities_list[0][0]
                    

    #             except:
    #                 is_safe = True
    #                 print("safe")
    #             pkg = requests_page.packages[0]
    #             pkg_params = {"name":pkg.project , "current_version":lib_version.strip() , "latest_version":pkg.version ,"digest":pkg.get_digests()['sha256'] , 'url':pkg.url ,'is_signed':pkg.has_sig ,'is_safe':is_safe ,'issue_title':Issues}
    #         except:
    #             pkg_params = {"name":stripped.strip() , "current_version":lib_version.strip() , "latest_version":"n/a" ,"digest":"n/a",'is_safe':is_safe ,'issue_title':Issues}

    #          # scan safety-db
            
    #     elif(library[0].data_mode == 'services'):
    #         url_path = "dashboard/service_vulncheck.html"
    #         pkg_params = {"name":stripped.strip() , "current_version":lib_version.strip() , "latest_version":"n/a" ,"digest":"n/a" ,'is_safe':is_safe}
            
    #     elif(library[0].data_mode == 'windows'):
    #         url_path = "dashboard/windows_vulncheck.html"
    #         try:
    #             vulners_api = vulners.Vulners(api_key="4QIYDKA0NXPHUWXJNQYLISIZEZZH8FM25YNK0L518VOWJJEOWO81XGMH2KSL81KJ")
    #             win_vulners = vulners_api.kbAudit(os="Windows Server 2012 R2", kb_list=[lib_version.strip()])
    #             need_2_install_kb = win_vulners['kbMissed']
    #             affected_cve = win_vulners['cvelist']
    #             print("_____affected cve_____")
    #             print(affected_cve[0])
    #             Affected_Cve = affected_cve

    #         except:
    #             is_safe = True
                
    #         pkg_params = {"name":stripped.strip() , "kb_name":lib_version.strip() , "latest_version":"n/a" ,"digest":"n/a",'is_safe':is_safe ,'affected_cve':Affected_Cve}
    #     else:pass
        


        
       

    #     data.append(pkg_params.copy())
    
        
           
 
    # print("------------------")
    # f.close()
    messages.add_message(request, messages.INFO, 'Vulnerabilities found , Email send to admin')
           
    context = {
        "item":"show all",
        "windows":windows ,
        "data":data
       
    }
    return render(request, url_path, context)



@login_required
def library_scan(request ,lib_id=None):
    library = Library.objects.filter(id=lib_id).order_by('-id')
    f = open(library[0].library_list.path, "r")
    print("------------------")

    lines = f.readlines()
    for line in lines:
        print(line)
    print("------------------")
    f.close()
    context = {
        "item":library[0], 
        "lines":lines
    }

    # send_mail(
    #     'Payment',
    #     'find payment.',
    #     'kidkudzy@gmail.com',
    #     ['kmakufa@outlook.com', 'promiseksystems@gmail.com'],
    #     fail_silently=False,
    # )

    
    return render(request, 'dashboard/library_view.html', context)
    
@login_required
def vuln_check(request ,lib_id=None):
    library = Library.objects.filter(id=lib_id).order_by('-id')
    f = open(library[0].library_list.path, "r")
    print("------------------")

    lines = f.readlines()

    data = []
    Issues = []
    Affected_Cve = []
    url_path = ""
   
    for line in lines:
        # here comes the vuln scanner logic
        sep = '=='
        stripped = line.split(sep, 1)[0]
        lib_version = line.split(sep, 1)[1]
        is_safe = False
        
        # print(line.strip())
        # print("-------without end-------")
        # print(line.split(sep, 1)[0])
        # print("------with end-----")
      
        # check updates and security
        with PyPISimple() as client:
            requests_page = client.get_project_page(stripped.strip())
        
        requests_page = client.get_project_page(stripped.strip())
        pkg_params = {}

        if(library[0].data_mode == 'application'):
            url_path = "dashboard/app_vulncheck.html"

            try:
                try:
                    vulners_api = vulners.Vulners(api_key="4QIYDKA0NXPHUWXJNQYLISIZEZZH8FM25YNK0L518VOWJJEOWO81XGMH2KSL81KJ")
                    results = vulners_api.softwareVulnerabilities(stripped.strip(), lib_version.strip())
                    # print(len(stripped.strip()))
                    # print(len(lib_version.strip()))
                    # results = vulners_api.softwareVulnerabilities("httpd", "1.3")
                    exploit_list = results.get('exploit')
                    vulnerabilities_list = [results.get(key) for key in results if key not in ['info', 'blog', 'bugbounty']]
                    print("vulneralibity type_____"+vulnerabilities_list[0][0]['type'])
                    print(vulnerabilities_list[0][0]['title'])
                    Issues = vulnerabilities_list[0][0]
                    

                except:
                    is_safe = True
                    print("safe")
                pkg = requests_page.packages[0]
                pkg_params = {"name":pkg.project , "current_version":lib_version.strip() , "latest_version":pkg.version ,"digest":pkg.get_digests()['sha256'] , 'url':pkg.url ,'is_signed':pkg.has_sig ,'is_safe':is_safe ,'issue_title':Issues}
            except:
                pkg_params = {"name":stripped.strip() , "current_version":lib_version.strip() , "latest_version":"n/a" ,"digest":"n/a",'is_safe':is_safe ,'issue_title':Issues}

             # scan safety-db
            
        elif(library[0].data_mode == 'services'):
            url_path = "dashboard/service_vulncheck.html"
            pkg_params = {"name":stripped.strip() , "current_version":lib_version.strip() , "latest_version":"n/a" ,"digest":"n/a" ,'is_safe':is_safe}

        elif(library[0].data_mode == 'windows'):
            url_path = "dashboard/windows_vulncheck.html"
            try:
                vulners_api = vulners.Vulners(api_key="4QIYDKA0NXPHUWXJNQYLISIZEZZH8FM25YNK0L518VOWJJEOWO81XGMH2KSL81KJ")
                win_vulners = vulners_api.kbAudit(os="Windows Server 2012 R2", kb_list=[lib_version.strip()])
                need_2_install_kb = win_vulners['kbMissed']
                affected_cve = win_vulners['cvelist']
                print("_____affected cve_____")
                print(affected_cve[0])
                Affected_Cve = affected_cve

            except:
                is_safe = True
                
            pkg_params = {"name":stripped.strip() , "kb_name":lib_version.strip() , "latest_version":"n/a" ,"digest":"n/a",'is_safe':is_safe ,'affected_cve':Affected_Cve}
        else:pass
        


        
       

        data.append(pkg_params.copy())
    
        
           
 
    print("------------------")
    f.close()
    context = {
        "item":library[0],
        "data":data 
       
    }
    return render(request, url_path, context)
@login_required
def delete_librabry(request ,librabry_id=None):
    library = Library.objects.get(pk=librabry_id)
    library.delete()
    messages.add_message(request, messages.INFO, 'Library deleted')
    return HttpResponseRedirect('/dashboard/libraries')


@login_required
def cve_scan(request):
    form = None
    url = "dashboard/view_by_cve.html" 
    cve_data = []
    if request.method == 'POST':
        url = "dashboard/cve_results.html"
        form = CVE_Scan_Form(request.POST)
        if(form.is_valid()):
           
            data = form.cleaned_data['cve_name']
            print("^^^^^^^^^^^")

            vulners_api = vulners.Vulners(api_key="4QIYDKA0NXPHUWXJNQYLISIZEZZH8FM25YNK0L518VOWJJEOWO81XGMH2KSL81KJ")
            cve_data = vulners_api.document(data)
            print(cve_data)
        
     
    else:
        form = CVE_Scan_Form()
    
    context = {
        
        'title': "Scan by Cve",
        'form':form,
        'cve_data':cve_data
        
    } 
     
    return render(request , url , context)