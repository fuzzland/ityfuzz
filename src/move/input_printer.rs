use std::fmt::Write;

use anyhow::{anyhow, Result};
use move_core_types::{account_address::AccountAddress, u256};
use move_vm_types::values::{Container, ContainerRef, IndexedRef, Value, ValueImpl};

pub fn print_value(val: &Value) -> String {
    let mut buf = String::new();
    print_value_impl(&mut buf, &val.0).unwrap();
    buf
}

fn print_value_impl<B: Write>(buf: &mut B, val: &ValueImpl) -> Result<()> {
    match val {
        ValueImpl::Invalid => print_invalid(buf),

        ValueImpl::U8(x) => print_u8(buf, x),
        ValueImpl::U16(x) => print_u16(buf, x),
        ValueImpl::U32(x) => print_u32(buf, x),
        ValueImpl::U64(x) => print_u64(buf, x),
        ValueImpl::U128(x) => print_u128(buf, x),
        ValueImpl::U256(x) => print_u256(buf, x),
        ValueImpl::Bool(x) => print_bool(buf, x),
        ValueImpl::Address(x) => print_address(buf, x),

        ValueImpl::Container(c) => print_container(buf, c),

        ValueImpl::ContainerRef(r) => print_container_ref(buf, r),
        ValueImpl::IndexedRef(r) => print_indexed_ref(buf, r),
    }
}

fn print_invalid<B: Write>(buf: &mut B) -> Result<()> {
    Ok(write!(buf, "-")?)
}

fn print_u8<B: Write>(buf: &mut B, x: &u8) -> Result<()> {
    Ok(write!(buf, "{}", x)?)
}

fn print_u16<B: Write>(buf: &mut B, x: &u16) -> Result<()> {
    Ok(write!(buf, "{}", x)?)
}

fn print_u32<B: Write>(buf: &mut B, x: &u32) -> Result<()> {
    Ok(write!(buf, "{}", x)?)
}

fn print_u64<B: Write>(buf: &mut B, x: &u64) -> Result<()> {
    Ok(write!(buf, "{}", x)?)
}

fn print_u128<B: Write>(buf: &mut B, x: &u128) -> Result<()> {
    Ok(write!(buf, "{}", x)?)
}

fn print_u256<B: Write>(buf: &mut B, x: &u256::U256) -> Result<()> {
    Ok(write!(buf, "{}", x)?)
}

fn print_bool<B: Write>(buf: &mut B, x: &bool) -> Result<()> {
    Ok(write!(buf, "{}", x)?)
}

fn print_address<B: Write>(buf: &mut B, x: &AccountAddress) -> Result<()> {
    Ok(write!(buf, "{}", x)?)
}

fn print_list<'a, B, I, X, F>(buf: &mut B, begin: &str, items: I, print: F, end: &str) -> Result<()>
where
    B: Write,
    X: 'a,
    I: IntoIterator<Item = &'a X>,
    F: Fn(&mut B, &X) -> Result<()>,
{
    write!(buf, "{}", begin)?;
    let mut it = items.into_iter();
    if let Some(x) = it.next() {
        print(buf, x)?;
        for x in it {
            write!(buf, ", ")?;
            print(buf, x)?;
        }
    }
    write!(buf, "{}", end)?;
    Ok(())
}

fn print_bytes<B: Write>(buf: &mut B, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        write!(buf, "\"\"")?;
    } else {
        write!(buf, "0x{}", hex::encode(bytes))?;
    }

    Ok(())
}

fn print_container<B: Write>(buf: &mut B, c: &Container) -> Result<()> {
    match c {
        Container::Vec(r) => print_list(buf, "[", r.borrow().iter(), print_value_impl, "]"),

        Container::Struct(r) => print_list(buf, "{ ", r.borrow().iter(), print_value_impl, " }"),

        Container::VecU8(r) => print_bytes(buf, r.borrow().as_ref()),
        Container::VecU16(r) => print_list(buf, "[", r.borrow().iter(), print_u16, "]"),
        Container::VecU32(r) => print_list(buf, "[", r.borrow().iter(), print_u32, "]"),
        Container::VecU64(r) => print_list(buf, "[", r.borrow().iter(), print_u64, "]"),
        Container::VecU128(r) => print_list(buf, "[", r.borrow().iter(), print_u128, "]"),
        Container::VecU256(r) => print_list(buf, "[", r.borrow().iter(), print_u256, "]"),
        Container::VecBool(r) => print_list(buf, "[", r.borrow().iter(), print_bool, "]"),
        Container::VecAddress(r) => print_list(buf, "[", r.borrow().iter(), print_address, "]"),

        Container::Locals(_) => Err(anyhow!("debug print - invalid container: Locals")),
    }
}

fn print_container_ref<B: Write>(buf: &mut B, r: &ContainerRef) -> Result<()> {
    let c = match r {
        ContainerRef::Local(container) | ContainerRef::Global { container, .. } => container,
    };

    print_container(buf, c)
}

fn print_slice_elem<B, X, F>(buf: &mut B, v: &[X], idx: usize, print: F) -> Result<()>
where
    B: Write,
    F: FnOnce(&mut B, &X) -> Result<()>,
{
    match v.get(idx) {
        Some(x) => print(buf, x),
        None => Err(anyhow!("ref index out of bounds")),
    }
}

fn print_indexed_ref<B: Write>(buf: &mut B, r: &IndexedRef) -> Result<()> {
    let idx = r.idx;
    let c = match &r.container_ref {
        ContainerRef::Local(container) | ContainerRef::Global { container, .. } => container,
    };

    match c {
        Container::Locals(r) | Container::Vec(r) | Container::Struct(r) => {
            print_slice_elem(buf, &r.borrow(), idx, print_value_impl)
        }

        Container::VecU8(r) => print_slice_elem(buf, &r.borrow(), idx, print_u8),
        Container::VecU16(r) => print_slice_elem(buf, &r.borrow(), idx, print_u16),
        Container::VecU32(r) => print_slice_elem(buf, &r.borrow(), idx, print_u32),
        Container::VecU64(r) => print_slice_elem(buf, &r.borrow(), idx, print_u64),
        Container::VecU128(r) => print_slice_elem(buf, &r.borrow(), idx, print_u128),
        Container::VecU256(r) => print_slice_elem(buf, &r.borrow(), idx, print_u256),
        Container::VecBool(r) => print_slice_elem(buf, &r.borrow(), idx, print_bool),
        Container::VecAddress(r) => print_slice_elem(buf, &r.borrow(), idx, print_address),
    }
}
