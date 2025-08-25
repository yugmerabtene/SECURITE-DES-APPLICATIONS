# Chapitre-02 — Gestion des permissions et contrôle d’accès

## 1) Objectifs pédagogiques

* Comprendre le modèle d’autorisations Django (utilisateurs, groupes, permissions).
* Concevoir un **RBAC** (Role-Based Access Control) propre et maintenable.
* Aller au-delà des permissions “modèle” avec les permissions **objet** grâce à `django-guardian`.
* Sécuriser vues Django et APIs (DRF) via décorateurs, mixins et classes de permissions.
* Tester et auditer les contrôles d’accès (unit tests, logs).

## 2) Pré-requis

* Django ≥ 4.2, connaissance de base de `auth`, vues, templates/DRF.
* Notions de CIA et OWASP (A01, A05, A07).

---

## 3) Modèle d’autorisations Django — Rappels et fondamentaux

### 3.1 Utilisateurs, is\_staff, is\_superuser, groupes

* `is_active`: compte actif (contrôle d’accès de base).
* `is_staff`: **autorise l’accès à l’admin Django** (ne confère pas d’autres droits).
* `is_superuser`: **bypass** de toutes les permissions (à limiter au strict nécessaire).
* **Groupes**: contiennent un set de permissions; les utilisateurs héritent des permissions du/des groupe(s).

### 3.2 Permissions “modèle”

* Créées automatiquement pour chaque modèle installé: `add_<model>`, `change_<model>`, `delete_<model>`, `view_<model>`.
* Vérification:

  ```python
  request.user.has_perm("app_label.add_article")
  request.user.has_perms(["app_label.view_article", "app_label.change_article"])
  ```
* Définir des permissions personnalisées:

  ```python
  # app/models.py
  class Article(models.Model):
      title = models.CharField(max_length=200)
      class Meta:
          permissions = [
              ("publish_article", "Peut publier un article"),
              ("moderate_article", "Peut modérer un article"),
          ]
  ```

### 3.3 Création initiale des rôles (Groupes) : bootstrap

* Commande de management (recommandé) pour créer/mettre à jour groupes + permissions:

  ```python
  # app/management/commands/bootstrap_roles.py
  from django.core.management import BaseCommand
  from django.contrib.auth.models import Group, Permission

  ROLES = {
      "utilisateur": ["app.view_article"],
      "moderateur": ["app.view_article", "app.change_article", "app.moderate_article"],
      "administrateur": ["app.add_article", "app.change_article", "app.delete_article",
                         "app.view_article", "app.publish_article", "app.moderate_article"],
  }

  class Command(BaseCommand):
      def handle(self, *args, **kwargs):
          for role, codename_list in ROLES.items():
              g, _ = Group.objects.get_or_create(name=role)
              perms = Permission.objects.filter(
                  content_type__app_label="app", codename__in=[c.split(".")[1] for c in codename_list]
              )
              g.permissions.set(perms)
              self.stdout.write(self.style.SUCCESS(f"Role {role} ok"))
  ```
* Exécuter après `migrate` pour garantir l’existence des permissions.

### 3.4 Attribution automatique d’un rôle à l’inscription (optionnel)

```python
# app/signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group

User = get_user_model()

@receiver(post_save, sender=User)
def add_default_role(sender, instance, created, **kwargs):
    if created:
        group = Group.objects.get(name="utilisateur")
        instance.groups.add(group)
```

* Activer dans `apps.py` pour enregistrer le signal.

---

## 4) Contrôle d’accès basé sur les rôles (RBAC)

### 4.1 Principes

* **Moindre privilège**: chaque rôle n’a que le strict nécessaire.
* **Deny-by-default**: si un droit n’est pas explicitement accordé, il est refusé.
* **Séparation des rôles**: “utilisateur”, “modérateur”, “administrateur” (exemple minimal).
* **Traçabilité**: modifications de rôles/permissions loguées (A09).

### 4.2 Modélisation simple des rôles

* Rôles = **Groupes Django**.
* Matrice d’accès (exemple):

  | Rôle           | view | add | change | delete | publish | moderate |
  | -------------- | ---- | --- | ------ | ------ | ------- | -------- |
  | utilisateur    | ✔︎   | ✖︎  | ✖︎     | ✖︎     | ✖︎      | ✖︎       |
  | moderateur     | ✔︎   | ✖︎  | ✔︎     | ✖︎     | ✖︎      | ✔︎       |
  | administrateur | ✔︎   | ✔︎  | ✔︎     | ✔︎     | ✔︎      | ✔︎       |

---

## 5) Sécurisation des vues Django (fonctionnelles ou CBV)

### 5.1 Décorateurs

* `@login_required`: impose l’authentification.
* `@permission_required("app.change_article", raise_exception=True)`: impose une permission précise.
* `@user_passes_test(lambda u: u.groups.filter(name="moderateur").exists())`: test arbitraire (à utiliser avec parcimonie).

### 5.2 Mixins (Class-Based Views)

```python
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.views.generic import UpdateView
from .models import Article

class ArticleUpdateView(LoginRequiredMixin, PermissionRequiredMixin, UpdateView):
    model = Article
    fields = ["title"]
    permission_required = "app.change_article"
    raise_exception = True  # renvoie 403 plutôt que rediriger
```

### 5.3 Filtrage du queryset par permissions

* Toujours restreindre côté serveur:

  ```python
  def get_queryset(self):
      qs = super().get_queryset()
      if self.request.user.has_perm("app.moderate_article"):
          return qs
      return qs.filter(author=self.request.user)  # exemple: accès restreint à ses objets
  ```

---

## 6) Sécurisation des APIs (Django REST Framework)

### 6.1 Permissions DRF intégrées

* `IsAuthenticated`, `IsAdminUser`, `AllowAny`.
* `DjangoModelPermissions`: mappe les actions CRUD aux permissions modèle.
* `DjangoObjectPermissions`: nécessite un backend objet (ex: guardian).

```python
# settings.py
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
}
```

```python
from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework import filters
from .models import Article
from .serializers import ArticleSerializer

class ArticleViewSet(ModelViewSet):
    queryset = Article.objects.all()
    serializer_class = ArticleSerializer
    authentication_classes = [SessionAuthentication, BasicAuthentication]
    permission_classes = [IsAuthenticated]  # + DjangoModelPermissions si souhaité
```

### 6.2 Permissions DRF personnalisées

```python
from rest_framework.permissions import BasePermission

class CanPublishArticle(BasePermission):
    def has_permission(self, request, view):
        return request.user.has_perm("app.publish_article")
```

---

## 7) Permissions objet (object-level) avec django-guardian

### 7.1 Installation et configuration

```bash
pip install django-guardian
```

```python
# settings.py
INSTALLED_APPS += ["guardian"]
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",     # permissions modèle
    "guardian.backends.ObjectPermissionBackend",     # permissions objet
]
ANONYMOUS_USER_NAME = "anonymous_user"
```

* `migrate` après installation.

### 7.2 Utilisation

```python
from guardian.shortcuts import assign_perm, remove_perm, get_objects_for_user
from .models import Article

# Accorder une permission objet
assign_perm("change_article", user, article_instance)

# Vérifier
user.has_perm("change_article", article_instance)

# Lister objets accessibles
qs = get_objects_for_user(user, "app.view_article", klass=Article)
```

### 7.3 Cas d’usage

* Modération par objet (un modérateur ne peut changer que certains articles).
* Partage fin document-par-document (RBAC + ACL objet).

> Bonnes pratiques: combiner **groupes** (rôles larges) + **permissions objet** (exceptions ponctuelles).

---

## 8) Tests et audit des contrôles d’accès

### 8.1 Tests unitaires

```python
from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from django.urls import reverse

class AccessTests(TestCase):
    def setUp(self):
        self.User = get_user_model()
        self.user = self.User.objects.create_user("u1", password="x")
        self.admin = self.User.objects.create_superuser("admin","a@a", "x")

    def test_dashboard_requires_login(self):
        resp = self.client.get("/dashboard/")
        self.assertEqual(resp.status_code, 302)  # redirection vers login

    def test_admin_bypass(self):
        self.client.force_login(self.admin)
        resp = self.client.get("/dashboard/")
        self.assertEqual(resp.status_code, 200)
```

### 8.2 Journalisation

* Loguer: accès refusés (403), escalades de droits, changements de groupe/permission.
* Conserver une **piste d’audit**: qui a accordé quel droit, quand.

---

## 9) Anti-patterns et pièges courants

* Se fier au **front-end** pour cacher des boutons sans vérifier côté serveur.
* Utiliser `is_staff` comme “administrateur applicatif” (il ne sert qu’à l’admin Django).
* Oublier de filtrer les **querysets** (exposition de données).
* Permissions “custom” non migrées (ou non re-créées après changement de `Meta.permissions`).
* Donner `is_superuser` au lieu d’un ensemble précis de permissions.

---

## 10) TP — Implémenter un RBAC (utilisateurs, modérateurs, administrateurs)

### 10.1 Objectifs

* Concevoir et implémenter un **RBAC** avec groupes/permissions.
* Sécuriser vues et APIs (DRF) avec mixins/décorateurs/classes de permissions.
* Optionnel: permissions objet avec `django-guardian`.

### 10.2 Contexte

* Application `blog/` avec `Article(title, body, author, is_published)`.
* Vues/API: liste, détail, création, édition, publication, suppression.

### 10.3 Rôles et droits

* **utilisateur**: `view_article` (ne voit que publiés) + créer ses articles (option).
* **moderateur**: `view_article`, `change_article`, `moderate_article` (peut éditer/publier).
* **administrateur**: tous droits (add/change/delete/view/publish/moderate).

### 10.4 Tâches

1. Créer permissions custom `publish_article`, `moderate_article` (Meta).
2. `bootstrap_roles` pour créer groupes + affecter permissions.
3. Protéger vues CBV avec `LoginRequiredMixin` + `PermissionRequiredMixin`.
4. DRF: `IsAuthenticated` + `DjangoModelPermissions` (ou permission custom).
5. Filtrer `queryset`:

   * Utilisateur: voit seulement `is_published=True` ou ses propres drafts.
   * Modérateur/Admin: voit tout.
6. (Option) `django-guardian`: donner `change_article` objet à un utilisateur spécifique.
7. Tests:

   * Accès interdit pour non authentifié.
   * Utilisateur ne peut pas publier/supprimer.
   * Modérateur peut modifier/publier.
   * Admin peut tout.
8. Logs: journaliser publication, suppression, changements de rôles.

### 10.5 Barème (sur 20)

* Rôles/permissions correctement créés et assignés: 5
* Sécurisation vues + DRF: 6
* Filtrage queryset robuste: 3
* Tests pertinents: 3
* Logs + option guardian (objet): 3

---

## 11) Checklist de mise en production (contrôle d’accès)

* Rôles documentés, “moindre privilège” appliqué.
* Aucun compte “technique” avec `is_superuser` en exploitation.
* Journalisation activée (403/permission denied, changements de droits).
* Revue de code: toute action sensible protégée par `has_perm(...)`.
* Jeux de données de test: vérifier **escalade horizontale/verticale**.
