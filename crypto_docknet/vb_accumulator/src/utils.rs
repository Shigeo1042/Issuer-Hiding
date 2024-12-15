// TODO: Following is the correct way to generate params but does not work
/*#[macro_export]
macro_rules! initial_elements {
    ($Fr: ident, $elems:expr) => {{
        let res = vec![];
        for e in $elems {
            res.push(field_new!($Fr, e));
        }
        res
    }};
}*/

#[macro_export]
macro_rules! initial_elements_for_bls12_381 {
    ($Fr: ident) => {{
        let mut res: Vec<$Fr> = vec![];
        res.push(MontFp!(
            "48702668752744056212524131907777588138266291225961714032791501307766539426092"
        ));
        res.push(MontFp!("228988810152649578064853576960394133503"));
        res.push(MontFp!(
            "46454669306535580442819773933076400553933878175571986080969841567332895786017"
        ));
        res.push(MontFp!(
            "45205798410695891408614168931997362660425926808089717551136866582122865413073"
        ));
        res.push(MontFp!(
            "34288838479222975534395827096705373067917615411464237264633937766591872085112"
        ));
        res.push(MontFp!(
            "92992352668298031901896044184055569161836568729514436393284062001611460666"
        ));
        res.push(MontFp!(
            "24304788127629790681951745309274362165984411810782330025478878507999651843060"
        ));
        res.push(MontFp!(
            "23682614706182920393234601202846423393145397933621008028884956856015126827098"
        ));
        res.push(MontFp!(
            "47983764596765232981592716782054734184223420327454065257761821043292139139799"
        ));
        res.push(MontFp!(
            "16637449727034532026669502917734913967753061896878734983059700689089422192450"
        ));
        res.push(MontFp!(
            "49543903940095721467774728926921205375104051833932232540372393802570589366958"
        ));
        res.push(MontFp!(
            "26899426916892720090059971370452737574507152537975350262743684140510311482771"
        ));
        res
    }};
}
