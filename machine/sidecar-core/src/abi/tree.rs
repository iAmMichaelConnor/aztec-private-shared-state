//! The ABI checks of a manifest's `tree` entries.

use super::*;

// The ABI checks of one `tree` entry (see `check_manifest`).
pub(super) fn check_tree(
    at: &str,
    tree: &TreeLayout,
    shape: &CircuitShape,
    returns: &Returns,
) -> Result<(), Refusal> {
    let bad = |field: String, why: String| {
        Err(Refusal::bad_request(format!("field `{at}.{field}`: {why}")))
    };
    let inputs = tree
        .index
        .iter()
        .map(|n| ("index", n))
        .chain(tree.count.iter().map(|n| ("count", n)))
        .chain(tree.window.iter().map(|w| ("window.start", &w.start)));
    for (field, name) in inputs {
        let wide = shape.params.iter().find(|p| {
            p.width != 1
                && matches!(&p.source, Source::Public(PublicSource::One(PublicOperand::Name(n))) if n == name)
        });
        if let Some(p) = wide {
            return bad(
                field.into(),
                format!(
                    "`{name}` fills `{}` of {} fields; an index input is one field",
                    p.name, p.width
                ),
            );
        }
    }
    if let Some(params) = &tree.params {
        let depth = tree.depth as usize;
        let mut widths = vec![
            ("params.old_hashes", &params.old_hashes, tree.probe),
            ("params.siblings", &params.siblings, tree.probe * depth),
            ("params.leaves", &params.leaves, tree.probe * tree.leaf_len),
        ];
        if let Some(indices) = &params.indices {
            widths.push(("params.indices", indices, tree.probe));
        }
        if let Some(w) = &tree.window {
            let above = depth - w.height() as usize;
            widths.extend([
                ("window.params.old_hashes", &w.params.old_hashes, w.width),
                ("window.params.siblings", &w.params.siblings, above),
                (
                    "window.params.leaves",
                    &w.params.leaves,
                    w.width * tree.leaf_len,
                ),
            ]);
        }
        for (field, name, width) in widths {
            let Some(param) = shape.param(name) else {
                return bad(field.into(), format!("`{name}` is not a parameter"));
            };
            if param.width != width {
                return bad(
                    field.into(),
                    format!(
                        "`{name}` has {} fields; the layout gives {width}",
                        param.width
                    ),
                );
            }
            if param.visibility == Visibility::Public {
                return bad(
                    field.into(),
                    format!(
                        "`{name}` is public; the tree's parameters are private (the contract's \
                         public inputs do not carry them)"
                    ),
                );
            }
        }
    }
    if let Some(name) = &tree.next_index {
        returns.public_field(&format!("{at}.next_index"), name)?;
    }
    if let Some(name) = &tree.new_hashes {
        let field = format!("{at}.new_hashes");
        let first = returns.public_field(&field, &format!("{name}[0]"))?;
        for i in 1..tree.probe {
            if returns.public_field(&field, &format!("{name}[{i}]"))? != first + i {
                return bad("new_hashes".into(), format!("`{name}` is not one array"));
            }
        }
        if returns
            .public_field(&field, &format!("{name}[{}]", tree.probe))
            .is_ok()
        {
            return bad(
                "new_hashes".into(),
                format!("`{name}` has more than probe = {} hashes", tree.probe),
            );
        }
    }
    Ok(())
}
