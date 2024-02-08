export interface VC {
  '@context': ['https://www.w3.org/2018/credentials/v1'];
  // A unique identifier for this VC
  id: string;
  // Issuer of the credential
  issuer: string;
  // https://www.w3.org/TR/vc-data-model/#issuance-date
  // @deprecated will be deprecated according to the next version of the VC data model
  issuanceDate: string;
  // Date and time from which the VC is valid. It is used to compute the starting period of the validity of the secret
  // https://www.w3.org/TR/vc-data-model-2.0/#validity-period
  validFrom: string;
  // schema of the credential
  credentialSchema: {
    id: string;
    type: 'FullJsonSchemaValidator2021';
  };
}
