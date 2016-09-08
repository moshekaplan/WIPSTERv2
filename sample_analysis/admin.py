from django.contrib import admin

from .models import Sample
from .models import BaseAnalysis

admin.site.register(Sample)
admin.site.register(BaseAnalysis)
