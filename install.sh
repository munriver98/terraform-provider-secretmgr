
version=$(basename $(ls -td ~/.terraform.d/plugins/doe/devops/secretmgr/* | head -1))

echo $version | awk -F '[.]' '{
    major=$1;
    minor=$2;
    patch=$3;
    patch += 1;
    # minor += mpatchinor / 100;
    # minor = minor % 100;
    printf( "%d.%d.%d\n", major, minor, patch );
    }' > version.txt

make install