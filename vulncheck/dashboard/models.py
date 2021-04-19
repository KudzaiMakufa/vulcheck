from django.db import models


class Library(models.Model):
    STATUS = (
        ('', '------------'),
        ('application', 'Application'),
        ('services', 'Services'),
        ('windows', 'Operating System: Windows'),
        ('linux', 'Operating System: Linux'),
        
    )

    application_name = models.CharField(default=None ,max_length=100)
    library_list = models.FileField(upload_to='uploads/')
    data_mode = models.CharField(blank=True , default='no' ,max_length=100 , choices = STATUS)
    created_at = models.DateField(default=None)
    updated_at = models.DateField(default=None)
    created_by = models.IntegerField(default=None)

    def __str__(self):
        return '%s' % self.application_name

class CVE_Scan(models.Model):
    

    cve_name = models.CharField(default=None ,max_length=100)


    def __str__(self):
        return '%s' % self.cve_name

