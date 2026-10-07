"""
Django Management Command: seed_testing_cases
Uploads and seeds real test case files (Case 1, 1.b, 2, 3) from C:\\Users\\VikashG\\Downloads\\Testing
into ForensiQ.
"""

from django.core.management.base import BaseCommand

from scripts.seed_testing_cases import seed_real_test_cases


class Command(BaseCommand):
    help = "Seeds the database with real forensic test cases (Case 1, 1.b, 2, 3)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--flush",
            action="store_true",
            help="Flush database prior to seeding real test cases.",
        )

    def handle(self, *args, **options):
        if options.get("flush"):
            from django.core.management import call_command

            self.stdout.write(self.style.WARNING("Flushing existing database records..."))
            call_command("flush", interactive=False)

        success = seed_real_test_cases()
        if success:
            self.stdout.write(self.style.SUCCESS("Successfully seeded real forensic test cases!"))
        else:
            self.stdout.write(self.style.ERROR("Failed to seed real test cases."))
