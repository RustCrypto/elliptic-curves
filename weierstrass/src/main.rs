use weierstrass;
use hex_literal::hex;
use generic_array::GenericArray;

use weierstrass::{GostTest256, AffinePoint, FieldElement};

type Scalar = weierstrass::Scalar<GostTest256>;
type ProjectivePoint = weierstrass::ProjectivePoint<GostTest256>;

fn main() {
    let _p: [u8; 32] = hex!("
        8000000000000000000000000000000000000000000000000000000000000431
    ");
    let e = hex!("
        2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5
    ");
    let d = hex!("
        7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28
    ");
    let k = hex!("
        77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3
    ");

    let k = Scalar::from_bytes_reduced(GenericArray::from_slice(&k));
    let d = Scalar::from_bytes_reduced(GenericArray::from_slice(&d));
    let e = Scalar::from_bytes_reduced(GenericArray::from_slice(&e));

    println!("k {:X}", k);

    let p = ProjectivePoint::generator();

    println!("x before {:X}", &p.x);
    println!("y before {:X}", &p.y);
    println!("z before {:X}", &p.z);

    let p = p * k;

    println!("x raw {:X}", &p.x);
    println!("y raw {:X}", &p.y);
    println!("z raw {:X}", &p.z);

    let p = p.to_affine();

    println!("x raw2 {:X}", &p.x);
    println!("y raw2 {:X}", &p.y);    

    print_hex("x ", &p.x.to_bytes());
    print_hex("y ", &p.y.to_bytes());

    let r = Scalar::from_bytes_reduced(&p.x.to_bytes());

    println!("r {:X}", r);

    let rd = r*d;
    println!("rd {:X}", rd);
    let ke = k*e;
    println!("ke {:X}", ke);

    let calc_s = rd + ke;

    println!("calc s {:X}", calc_s);



    println!("verification");

    let r = hex!("
        41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493
    ");
    let s = hex!("
        01456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40
    ");
    let xq = hex!("
        7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B
    ");
    let yq = hex!("
        26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA
    ");

    let r = Scalar::from_repr(*GenericArray::from_slice(&r)).unwrap();
    let s = Scalar::from_repr(*GenericArray::from_slice(&s)).unwrap();

    println!("r {:X}", r);
    println!("s {:X}", s);

    let v = e.invert().unwrap();
    println!("v {:X}", v);

    let z1 = s*v;
    let z2 = -r*v;
    println!("z1 {:X}", z1);
    println!("z2 {:X}", z2);

    let q = AffinePoint {
        x: FieldElement::from_bytes(GenericArray::from_slice(&xq)).unwrap(),
        y: FieldElement::from_bytes(GenericArray::from_slice(&yq)).unwrap(),
        infinity: subtle::Choice::from(0),
    };

    let c = ProjectivePoint::generator()*z1 + ProjectivePoint::from(q)*z2;
    let c = c.to_affine();

    print_hex("xc ", &c.x.to_bytes());
    print_hex("yc ", &c.y.to_bytes());

    let r = Scalar::from_bytes_reduced(&c.x.to_bytes());
    println!("r: {:X}", r);
}


fn print_hex(s: &str, buf: &[u8]) {
    print!("{}", s);
    for b in buf {
        print!("{:02X}", b);
    }
    println!();
}
