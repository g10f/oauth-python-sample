from datetime import timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone

from ...models import IdToken, AccessToken, RefreshToken, Nonce, MAX_AGE


class Command(BaseCommand):
    help = "Can be run as a cronjob or directly to clean out expired tokens."

    def handle(self, *args, **options):
        IdToken.objects.filter(expires_at__lt=timezone.now()).delete()
        AccessToken.objects.filter(expires_at__lt=timezone.now()).delete()
        RefreshToken.objects.filter(expires_at__lt=timezone.now()).delete()
        Nonce.objects.filter(timestamp__lt=timezone.now() - timedelta(seconds=MAX_AGE)).delete()
