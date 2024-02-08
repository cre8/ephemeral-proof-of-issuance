export interface VcStatus {
  // unique identifier
  s_id: string;
  // secret that is used to calculate the hash
  secret: string;
  // if the vc is valid or not
  valid: boolean;
}
