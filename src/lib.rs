use nom::{
    bytes::complete::{tag, take}, multi::many0, number::complete::{be_u16, le_u16, le_u8}, IResult
};

const SIGNATURE: &[u8]="**TI83F*\x1A\x0A".as_bytes();
pub struct AppVar {
    pub comment: [u8;42],
    pub product_id: u8,
    pub var_entries: Vec<VarEntry>
}
pub fn parse_appvar(input: &[u8],verify_checksum:bool) -> IResult<&[u8], AppVar> {
    let (input, _) = signature(input)?;
    let (input, product_id) = product_id(input)?;
    let (input, comment) = comment(input)?;
    let (input, len) = appvar_data_len(input)?;
    let (input, data_section) = data_section(input, len)?;
    let (_, vars)=appvar_data_section(data_section)?;
    if verify_checksum{
        checksum(input,data_section)?;
    }
    Ok((
        input,
        AppVar {
            comment: comment.try_into().unwrap(),
            product_id,
            var_entries:vars
        },
    ))
}
#[derive(Debug)]
pub struct VarEntry {
    pub type_id: u8,
    pub data: Vec<u8>,
    pub name: [u8;8],
    pub archived: bool,
    pub version: u8,
}
impl AppVar{
    pub fn encode(&self)->Vec<u8>{
        let mut encoded_entries=Vec::new();
        for entry in &self.var_entries{
            let flag:u8=entry.archived.into();
            let entry_len=&(entry.data.len() as u16).to_le_bytes();
            let this_one_data=[&13u16.to_le_bytes()[..],entry_len,&[entry.type_id],&entry.name,&[entry.version],&[flag],entry_len,&entry.data];
            let mut this_one=this_one_data.concat();
            encoded_entries.append(&mut this_one)
        }
        [SIGNATURE,&[self.product_id],&self.comment,&(encoded_entries.len() as u16).to_le_bytes(),&encoded_entries,&gen_checksum(&encoded_entries)].concat()
    }
}
fn variable_entry(i: &[u8]) -> IResult<&[u8], VarEntry> {
    let (input, _) = header_type(i)?;
    let (input, len) = appvar_data_len(input)?;
    let (input, type_id) = var_type_id(input)?;
    let (input, name) = var_name(input)?;
    let (input, version) = le_u8(input)?;
    let (input, flag_num) = le_u8(input)?;
    let archived = matches!(flag_num,0x80);
    let (input, _) = entry_data_len(input)?;
    let (input, data) = data_section(input, len)?;
    Ok((
        input,
        VarEntry {
            type_id,
            version,
            archived,
            name:name.try_into().unwrap(),
            data: data.to_vec(),
        },
    ))
}
fn gen_checksum(data: &[u8])->[u8;2]{
    let sum=data.iter().fold(0u64, |counter,num|{
        counter+*num as u64
    });
    let lower_16=&sum.to_le_bytes()[..2];
    lower_16.try_into().unwrap()
}
fn checksum<'a>(i: &'a [u8],data: &'a [u8])->IResult<&'a [u8],&'a [u8]>{
    let sum=gen_checksum(data);
    tag(sum)(i)
}
fn appvar_data_section(i: &[u8])->IResult<&[u8],Vec<VarEntry>>{
    many0(variable_entry)(i)
}
fn var_name(i: &[u8]) -> IResult<&[u8], &[u8]> {
    take(8usize)(i)
}
fn var_type_id(i: &[u8]) -> IResult<&[u8], u8> {
    le_u8(i)
}
fn header_type(i: &[u8]) -> IResult<&[u8], ()> {
    let (input, _) = tag(&13u16.to_le_bytes())(i)?;
    Ok((input, ()))
}
fn product_id(i: &[u8]) -> IResult<&[u8], u8> {
    le_u8(i)
}
fn data_section(i: &[u8], len: u16) -> IResult<&[u8], &[u8]> {
    take(len)(i)
}
fn comment(i: &[u8]) -> IResult<&[u8], &[u8]> {
    take(42usize)(i)
}
fn signature(i: &[u8]) -> IResult<&[u8], &[u8]> {
    tag(SIGNATURE)(i)
}
fn appvar_data_len(i: &[u8]) -> IResult<&[u8], u16> {
    le_u16(i)
}

fn entry_data_len(i: &[u8]) -> IResult<&[u8], u16> {
    be_u16(i)
}