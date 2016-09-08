from django import forms
from .models import Sample

class UploadSampleForm(forms.ModelForm):
    class Meta:
        model = Sample
        fields = ('samplefile', 'ticket')
