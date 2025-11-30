# Maintainer: Dexmachi caiorocoli@gmail.com
pkgname=chaos-secrets
pkgver=0.1.0
pkgrel=1
pkgdesc="Declarative secrets manager for Arch Linux."
arch=('any')
_gitname="chaos-secrets"
url="https://github.com/Ch-aOS-Ch/chaos-secrets"
license=('MIT')
depends=('ch-aos')
makedepends=('python' 'python-pip' 'python-setuptools' 'python-wheel' 'uv')
source=("${_gitname}-$pkgver.tar.gz::$url/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('SKIP')

package() {
  cd "$srcdir/${_gitname}-$pkgver"

  uv build 2>/dev/null

  install -d "$pkgdir/usr/share/chaos/plugins/"

  install -m644 dist/*.whl "$pkgdir/usr/share/chaos/plugins/"
}
