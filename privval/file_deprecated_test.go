package privval_test

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tendermint/tendermint/privval"
)

const lastSignBytes = "6C080211085100000000000022480A2023A8C65085F5833939B6A8EC2DB" +
	"2993E8756B3A376ECB63DDC97452CC286B81112240A2016CE70F9C99C0A" +
	"46EBBED94D0D4C55AC47A2CA9C8046C05965B987FE8D70AEFB10012A0C0" +
	"8C3F8BCF20510D8F7C1EB013207746573744E6574"

const oldPrivvalContent = `{
  "address": "0591BD05426263A248A464C1CDA891AF4013A577",
  "pub_key": {
    "type": "tendermint/PubKeySm2",
    "value": "AV0eSinoYv2baEJiuJJ0oJ33Eha0kISwsoqgWQC+iBpm"
  },
  "last_height": "5",
  "last_round": "0",
  "last_step": 3,
  "last_signature": "Q7/cItTcsOY3eupv7s53cxOpXHeaWg8ARsDmj9FCYU36xEQ/wnlQA25AB0GNtww5CGrIEwPQcvrUj8oTMps1NA==",
  "last_signbytes": "` + lastSignBytes + `",
  "priv_key": {
    "type": "tendermint/PrivKeySm2",
    "value": "9yeVNqq98dXbiy33hp8ZUGTwRl8ubp3HMqyeybUUxs0="
  }
}`

func TestLoadAndUpgrade(t *testing.T) {

	oldFilePath := initTmpOldFile(t)
	defer os.Remove(oldFilePath)
	newStateFile, err := ioutil.TempFile("", "priv_validator_state*.json")
	defer os.Remove(newStateFile.Name())
	require.NoError(t, err)
	newKeyFile, err := ioutil.TempFile("", "priv_validator_key*.json")
	defer os.Remove(newKeyFile.Name())
	require.NoError(t, err)

	oldPV, err := privval.LoadOldFilePV(oldFilePath)
	assert.NoError(t, err)
	newPV := oldPV.Upgrade(newKeyFile.Name(), newStateFile.Name())

	assertEqualPV(t, oldPV, newPV)
	assert.NoError(t, err)
	upgradedPV := privval.LoadFilePV(newKeyFile.Name(), newStateFile.Name())
	assertEqualPV(t, oldPV, upgradedPV)
	oldPV, err = privval.LoadOldFilePV(oldFilePath + ".bak")
	require.NoError(t, err)
	assertEqualPV(t, oldPV, upgradedPV)
}

func assertEqualPV(t *testing.T, oldPV *privval.OldFilePV, newPV *privval.FilePV) {
	assert.Equal(t, oldPV.Address, newPV.Key.Address)
	assert.Equal(t, oldPV.Address, newPV.GetAddress())
	assert.Equal(t, oldPV.PubKey, newPV.Key.PubKey)
	assert.Equal(t, oldPV.PubKey, newPV.GetPubKey())
	assert.Equal(t, oldPV.PrivKey, newPV.Key.PrivKey)

	assert.Equal(t, oldPV.LastHeight, newPV.LastSignState.Height)
	assert.Equal(t, oldPV.LastRound, newPV.LastSignState.Round)
	assert.Equal(t, oldPV.LastSignature, newPV.LastSignState.Signature)
	assert.Equal(t, oldPV.LastSignBytes, newPV.LastSignState.SignBytes)
	assert.Equal(t, oldPV.LastStep, newPV.LastSignState.Step)
}

func initTmpOldFile(t *testing.T) string {
	tmpFile, err := ioutil.TempFile("", "priv_validator_*.json")
	require.NoError(t, err)
	t.Logf("created test file %s", tmpFile.Name())
	_, err = tmpFile.WriteString(oldPrivvalContent)
	require.NoError(t, err)

	return tmpFile.Name()
}
