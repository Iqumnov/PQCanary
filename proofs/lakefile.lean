import Lake
open Lake DSL

package «pqcanary_proofs» {
  -- add package configuration options here
}

lean_lib «HoTT_PQC» {
  -- add library configuration options here
}

@[default_target]
lean_exe «verify_pqc» {
  root := `Main
}

