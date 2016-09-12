from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.http import Http404
from django.utils import timezone
from django.template.loader import render_to_string
from django.shortcuts import render

from .models import Sample, BaseAnalysis, PEAnalysis, PDFAnalysis, DOCAnalysis, RTFAnalysis, PluginAnalysis
from .forms import UploadSampleForm



def index(request):
    return HttpResponse("Sample Analysis index.")

# Determine the type of file based on the filetype output
def check_is_exe(filetype):
    return "PE32" in filetype and "Windows" in filetype

def check_is_pdf(filetype):
    return "PDF" in filetype
    
def check_is_doc(filetype):
    return "Document File V2" in filetype
    
def check_is_rtf(filetype):
    return "Rich Text Format" in filetype


# These classes are used for generating the output
class Entry:
    def __init__(self, title, value, entry_type='single'):
        self.title = title
        self.value = value
        self.entry_type = entry_type

class Group:
    def __init__(self, title, entries=None):
        self.title = title
        if entries:
            self.entries = entries
        else:
            self.entries = []
            
    def add_entry(self, title, value, entry_type='single'):
        entry = Entry(title, value, entry_type)
        self.entries.append(entry)
        return entry
        
    def get_entry(self, title):
        for entry in self.entries:
            if entry.title == title:
                return entry

class Tab:
    def __init__(self, title, groups=None):
        self.title = title
        self.anchortext = title.replace(' ', '_')
        if groups:
            self.groups = groups
        else:
            self.groups = []
    
    def add_group(self, title, entries=None):
        group = Group(title, entries)
        self.groups.append(group)
        return group
        
    def get_group(self, title):
        for group in self.groups:
            if group.title == title:
                return group
                

class AnalysisOutputDisplay:
    def __init__(self):
        self.tabs = []
        
    def add_tab(self, title, groups=None):
        tab = Tab(title, groups)
        self.tabs.append(tab)
        return tab

def create_plaintext_report(sample, base_analysis, analysis_output):
    template = render_to_string('sample_analysis/plaintext_report.html',
                                {   'tabs':analysis_output.tabs, 
                                    'sample':sample, 
                                    'base_analysis':base_analysis})
    return template

    
def display_report_by_sha256(request, sha256):
    sample = Sample.objects.filter(sha256=sha256).first()
    base_analysis = BaseAnalysis.objects.filter(sample=sample).first()
    
    if sample is None or base_analysis is None:
        raise Http404("File with a sha256 of: '%s' is not in the database!" % sha256)

    return analysis_output(request, sample, base_analysis)


def display_report_by_md5(request, md5):
    sample = Sample.objects.filter(md5=md5).first()
    base_analysis = BaseAnalysis.objects.filter(sample=sample).first()
    
    if sample is None or base_analysis is None:
        raise Http404("File with a md5 of: '%s' is not in the database!" % md5)

    return analysis_output(request, sample, base_analysis)


def analysis_output(request, sample, base_analysis):

    analysis_output = AnalysisOutputDisplay()
    # Summary tab always goes first
    tab_summary = analysis_output.add_tab("Summary")
    group_basic = tab_summary.add_group("Basic Info")
    group_basic.add_entry("Filename", sample.filename[:30])  
    group_basic.add_entry("Ticket No.", sample.ticket)
    group_basic.add_entry("Submission Date", sample.created)
    group_basic.add_entry("Size", str(sample.size) + " bytes")
    group_basic.add_entry("MD5", sample.md5)
    group_basic.add_entry("SHA1", sample.sha1)
    group_basic.add_entry("SHA256", sample.sha256)
    group_basic.add_entry("FUZZY", sample.ssdeep)                   
    
    if base_analysis.ssdeep_compare:
        group_ssdeep = tab_summary.add_group("SSDEEP Comparison")
        group_ssdeep.add_entry("Similar to", base_analysis.ssdeep_compare)

    if base_analysis.vt_short:
        group_ssdeep = tab_summary.add_group("VirusTotal Results")
        group_ssdeep.add_entry("", base_analysis.vt_short)
        
    # Metadata tab:
    tab_metadata = analysis_output.add_tab("Metadata")
    group_filetype = tab_metadata.add_group("Filetype")    
    group_filetype.add_entry("", base_analysis.filetype, 'multiline')
    group_trid = tab_metadata.add_group("TriD")
    group_trid.add_entry("", base_analysis.trid, 'multiline')
    group_exif = tab_metadata.add_group("EXIF")
    group_exif.add_entry("", base_analysis.exif, 'multiline')
    

    # String Data tab:
    tab_string = analysis_output.add_tab("String Data")
    group_balbuzard = tab_string.add_group("Balbuzard")
    group_balbuzard.add_entry("", base_analysis.balbuzard, 'multiline')
    group_strings = tab_string.add_group("Strings")
    group_strings.add_entry("", base_analysis.strings, 'multiline')
    
    # Check the filetype to run type-specific analysis:
    filetype = base_analysis.filetype
    is_exe = check_is_exe(filetype)
    is_pdf = check_is_pdf(filetype)
    is_doc = check_is_doc(filetype)
    is_rtf = check_is_rtf(filetype)
    # Types are mutually exclusive
    assert sum([is_exe, is_pdf, is_doc, is_rtf]) < 2

    # EXE tab
    if is_exe:
        pe_analysis = PEAnalysis.objects.filter(sample=sample).first()
        if pe_analysis:
            tab_exe = analysis_output.add_tab("EXE Analysis")
            group_peframe = tab_metadata.add_group("peframe")
            group_peframe.add_entry("", pe_analysis.peframe, 'multiline')
            group_pescanner = tab_metadata.add_group("pescanner")
            group_pescanner.add_entry("", pe_analysis.pescanner, 'multiline')

    # PDF tab
    if is_pdf:
        pdf_analysis = PDFAnalysis.objects.filter(sample=sample).first()
        if pdf_analysis:
            tab_pdf = analysis_output.add_tab("PDF Analysis")
            
            group_pdfid = tab_pdf.add_group("pdfid")
            group_pdfid.add_entry("", pdf_analysis.pdfid, 'multiline')
            
            group_peepdf = tab_pdf.add_group("peepdf")
            group_peepdf.add_entry("", pdf_analysis.peepdf, 'multiline')
            
            group_pdfstrings = tab_pdf.add_group("pdfstrings")
            group_pdfstrings.add_entry("", pdf_analysis.pdfstrings, 'multiline')

    # DOC tab
    if is_doc:
        doc_analysis = DOCAnalysis.objects.filter(sample=sample).first()
        if doc_analysis:
            tab_doc = analysis_output.add_tab("DOC Analysis")
            
            group_oleid = tab_doc.add_group("oleid")
            group_oleid.add_entry("", doc_analysis.oleid, 'multiline')
            
            group_olemeta = tab_doc.add_group("olemeta")
            group_olemeta.add_entry("", doc_analysis.olemeta, 'multiline')
            
            group_olevba = tab_doc.add_group("olevba")
            group_olevba.add_entry("", doc_analysis.olevba, 'multiline')


    # RTF tab
    if is_rtf:
        rtf_analysis = RTFAnalysis.objects.filter(sample=sample).first()
        if rtf_analysis:
            tab_rtf = analysis_output.add_tab("RTF Analysis")
            
            group_rtfobj = tab_rtf.add_group("oleid")
            group_rtfobj.add_entry("", rtf_analysis.rtfobj, 'multiline')
    
            
    # The last tab is always the plaintext output:
    plaintext_data = create_plaintext_report(sample, base_analysis, analysis_output)
    
    tab_plaintext = analysis_output.add_tab("Plaintext")
    group_plaintext = tab_plaintext.add_group("Plaintext")
    group_plaintext.add_entry("", plaintext_data, 'multiline')
    
    return render(request, 'sample_analysis/analysis_output.html', {'tabs':analysis_output.tabs})                                                      
                                                       
    
def upload_form(request):
    valid_form = False
    if request.method == 'POST':
        form = UploadSampleForm(request.POST, request.FILES)
        if form.is_valid():
            valid_form = True
            
    if valid_form:
        sample = Sample.create(
            sample=request.FILES['samplefile'],
            ticket=request.POST['ticket']
        )
        sample.save()
        # Run the base analysis:
        base_analysis = BaseAnalysis.create(sample)
        base_analysis.save()
        
        # Check the filetype to run type-specific analysis:
        filetype = base_analysis.filetype
        is_exe = check_is_exe(filetype)
        is_pdf = check_is_pdf(filetype)
        is_doc = check_is_doc(filetype)
        is_rtf = check_is_rtf(filetype)
        # Types are mutually exclusive
        assert sum([is_exe, is_pdf, is_doc, is_rtf]) < 2

        if is_exe:
            PEAnalysis.create(sample).save()
        elif is_pdf:
            PDFAnalysis.create(sample).save()
        elif is_doc:
            DOCAnalysis.create(sample).save()
        elif is_rtf:
            RTFAnalysis.create(sample).save()
        
        newpage = "/sample_analysis/sha256/" + sample.sha256 + "/?upload=True"

        return HttpResponseRedirect(newpage)
    else:
        form = UploadSampleForm()
        samples = Sample.objects.filter(created__lte=timezone.now()).order_by('-id')[:25]
        return render(request, 'sample_analysis/upload_form.html', {'form': form, 'samples': samples})
