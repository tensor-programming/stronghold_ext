use iota_stronghold::{
    procedures::{Procedure, ProcedureError, Runner},
    Client, Location,
};

/// Trait defines the input and output types of a procedure.  Different types of procs contain input and output types where the inputs and outputs refer to
/// locations inside of the stronghold vault.
pub trait ProcedureExt {
    fn input(&self) -> Option<Location>;
    fn output(&self) -> Option<Location>;
}

/// Executes a cryptographic extension [`Procedure`] on a stronghold [`Client`] and returns its output.
/// the procedure must implement the [`Procedure`] and [`ProcedureExt`] traits.
pub fn execute_procedure_ext<P>(client: &Client, procedure: P) -> Result<P::Output, ProcedureError>
where
    P: Procedure + ProcedureExt,
{
    let res = execute_procedure_chained_ext(client, vec![procedure]);
    let mapped = res.map(|mut v| v.pop().unwrap())?;
    Ok(mapped)
}

/// Executes a set of cryptographic extension [`Procedure`]s on a stronghold [`Client`] and returns their outputs in a [`Vec`].
/// Cannot execute [`StrongholdProcedure`]s.
pub fn execute_procedure_chained_ext<T>(
    client: &Client,
    procedures: Vec<T>,
) -> Result<Vec<T::Output>, ProcedureError>
where
    T: Procedure + ProcedureExt,
{
    let mut out = Vec::new();
    let mut log = Vec::new();

    for proc in procedures {
        if let Some(output) = proc.output() {
            log.push(output);
        }
        let output = match proc.execute(client) {
            Ok(o) => o,
            Err(e) => {
                for location in log {
                    let _ = client.revoke_data(&location);
                }
                return Err(e);
            }
        };
        out.push(output);
    }
    Ok(out)
}
