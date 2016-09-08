from __future__ import unicode_literals
import os

from django.db import models
from django.utils import timezone
from django.core.files.storage import FileSystemStorage

import base_analysis

#######################################
# Helper Objects
#######################################

# Based on: http://stackoverflow.com/a/15900958
class HashFileSystemStorage(FileSystemStorage):
    def get_available_name(self, name, max_length=None):
        return name

    def _exists(name):
        pass
    
    def _save(self, name, content):
        if self.exists(name):
            # If the file exists, do not call the superclasses _save method
            return name
        # if the file is new, create it
        return super(HashFileSystemStorage, self)._save(name, content)


def hash_to_file_path(sha256):
    # Split the files into separate directories based on their SHA256 hash
    # A file with the hash of AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD... would be stored in:
    # sample_analysis\samples\AAAAAAAA\AAAAAAAABBBBBBBB\AAAAAAAABBBBBBBBCCCCCCCC\AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD...
    dest = os.path.join('sample_analysis', 'samples', sha256[:16], sha256[:32], sha256[:48], sha256)
    return dest


def hash_file_path(instance, filename):
    # The instance object must include the SHA256
    dest = hash_to_file_path(instance.sha256)
    return dest

#######################################
# Models
#######################################


class Sample(models.Model):
    samplefile = models.FileField(upload_to=hash_file_path, storage=HashFileSystemStorage())
    filename = models.CharField(max_length=256)
    size = models.IntegerField()
    ticket = models.CharField(max_length=32, default='')
    created = models.DateTimeField(default=timezone.now)

    md5 = models.CharField(max_length=32, db_index=True)
    sha1 = models.CharField(max_length=40)
    sha256 = models.CharField(max_length=64, db_index=True)
    ssdeep = models.CharField(max_length=148)

    def __str__(self):
        return self.filename
        
    def __unicode__(self):
        if isinstance(self.filename, unicode):
            return self.filename
        else:
            return unicode(self.filename,'utf-8')

    @classmethod
    def create(cls, sample, ticket):
        md5, sha1, sha256, ssdeep = base_analysis.get_hashes(sample)        
        sample = cls(   samplefile=sample,
                        filename = sample.name,
                        size=sample.size,
                        ticket=ticket,
                        md5=md5,
                        sha1=sha1,
                        sha256=sha256,
                        ssdeep=ssdeep
                    )
        
        return sample


#class Analysis(models.Model):
#    pass

class BaseAnalysis(models.Model):
    sample = models.ForeignKey(Sample, on_delete=models.CASCADE, db_index=True)
    ssdeep_compare = models.TextField()
    filetype = models.CharField(max_length=256, default='')
    trid = models.TextField() 
    exif = models.TextField(default='') 
    vt = models.TextField(default='')
    vt_short = models.TextField(default='')

    strings = models.TextField(default='')
    balbuzard = models.TextField(default='')
    
    
    @classmethod
    def create(cls, sample):
        fpath = os.path.abspath(hash_to_file_path(sample.sha256))

        ssdeep_compare = base_analysis.ssdeep_compare(sample.ssdeep, sample.md5, Sample.objects.all())
        baseanalysis = cls(
                sample=sample,
                ssdeep_compare=ssdeep_compare,
                filetype=base_analysis.get_filetype(sample.samplefile),
                trid=base_analysis.get_trid(fpath),
                exif=base_analysis.get_exif(fpath),
                strings=base_analysis.get_strings(fpath),
                balbuzard=base_analysis.get_balbuzard(fpath),
            )
        return baseanalysis


class PEAnalysis(models.Model):
    sample = models.ForeignKey(Sample, on_delete=models.CASCADE, db_index=True)
    peframe = models.TextField(default='') 
    pescanner = models.TextField(default='')
    
    @classmethod
    def create(cls, sample):
        fpath = os.path.abspath(hash_to_file_path(sample.sha256))

        analysis = cls(
                sample=sample,
                peframe=base_analysis.get_peframe(fpath),
                pescanner=base_analysis.get_pescanner(fpath),
            )
        return analysis


class PDFAnalysis(models.Model):
    sample = models.ForeignKey(Sample, on_delete=models.CASCADE, db_index=True)
    pdfid = models.TextField(default='')
    peepdf = models.TextField(default='')
    pdfstrings = models.TextField(default='')
    
    @classmethod
    def create(cls, sample):
        fpath = os.path.abspath(hash_to_file_path(sample.sha256))

        analysis = cls(
                sample=sample,
                pdfid=base_analysis.get_pdfid(fpath),
                peepdf=base_analysis.get_peepdf(fpath),
                pdfstrings=base_analysis.get_pdfstrings(fpath),
            )
        return analysis

class DOCAnalysis(models.Model):
    sample = models.ForeignKey(Sample, on_delete=models.CASCADE, db_index=True)
    oleid = models.TextField(default='')
    olemeta = models.TextField(default='')
    olevba = models.TextField(default='')
    
    @classmethod
    def create(cls, sample):
        fpath = os.path.abspath(hash_to_file_path(sample.sha256))
            
        oleid = handler.get_oleid(fpath)
        
        #If valid OLE file, run OLEMETA
        olematch = re.compile(r'\|\s+OLE format\s+\|\s+True\s+\|')
        if olematch.search(oleid):
            olemeta = handler.get_olemeta(fpath)
        else:
            olemeta = 'No ole metadata detected'
            
        #If VBA code detected, run OLEVBA
        vbamatch = re.compile(r'\|\s+VBA Macros\s+\|\s+True\s+\|')
        if vbamatch.search(oleid):
            olevba = handler.get_olevba(fpath)
        else:
            olevba = 'No vba detected'
            
        analysis = cls(
                sample=sample,
                oleid=oleid,
                olemeta=olemeta,
                olevba=olevba,
            )
        return analysis


class RTFAnalysis(models.Model):
    sample = models.ForeignKey(Sample, on_delete=models.CASCADE, db_index=True)
    rtfobj = models.TextField(default='')

    @classmethod
    def create(cls, sample):
        fpath = os.path.abspath(hash_to_file_path(sample.sha256))

        analysis = cls(
                sample=sample,
                rtfobj=base_analysis.get_rtfobj(fpath)
            )
        return analysis


class PluginAnalysis(models.Model):
    sample = models.ForeignKey(Sample, on_delete=models.CASCADE, db_index=True)
    tool_name = models.CharField(max_length=64)
    tool_version = models.CharField(max_length=64)
    
    tab_title = models.CharField(max_length=64)
    group_title = models.CharField(max_length=64)
    entry_title = models.CharField(max_length=64)
    entry_value = models.TextField(default='')
    entry_type = models.CharField(max_length=64)
    
    def __str__(self):
        return self.tool_name + ' version: ' + self.tool_version


