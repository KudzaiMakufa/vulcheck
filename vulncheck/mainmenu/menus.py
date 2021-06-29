MENUS = {
    'NAV_MENU_LEFT': [

     

        # {
        #     "name": "View Patients",
        #     "url": "#",
        #     "icon_class": 'mdi mdi-file-cabinet',
        #     # "validators": [
        #     #             ('mainmenu.menu_validators.has_group' ,'doctor'),
        #     #         ],
                    
        # },

               # another section
        {
            "name": "Libraries",
            "url": "#",
            "icon_class": 'mdi mdi-google-analytics',
            "submenu": [
                {
                    "name": "All Libraries",
                    "url": "dashboard:libraries",
                    
                    
                    
                },
                {
                    "name": "Add Library",
                    "url": "dashboard:create",     
                    
                },
                 {
                    "name": "Scan All",
                    "url": "dashboard:scan_all",     
                    
                },
                {
                    "name": "Scan By CVE",
                    "url": "dashboard:cve_scan",     
                    
                },
               
          
          
          
            
            ],
        },

    ]
}

