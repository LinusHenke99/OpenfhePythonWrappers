import neuralpy


def main() -> None:
    # Setting up parameters for FHE
    params = neuralpy.Parameters()
    params.SetMultiplicativeDepth(9)
    params.SetFirstModSize(35)
    params.SetScalingModSize(30)
    params.SetSecurityLevel(neuralpy.HEStd_128_classic)
    params.SetBatchSize(1024)
    params.SetScalingTechnique(neuralpy.FLEXIBLEAUTO)

    # Generating context object and enabling features
    context = neuralpy.MakeContext(params)
    context.Enable(neuralpy.PKE)
    context.Enable(neuralpy.LEVELEDSHE)
    context.Enable(neuralpy.KEYSWITCH)
    context.Enable(neuralpy.ADVANCEDSHE)

    print("Context with ring dimension: {}".format(context.GetRingDimension()))

    # Key generation
    keypair = context.KeyGen()

    print("Generating muliplication keys...")
    context.EvalMultKeyGen(keypair.privateKey)
    print("Done!")

    print("Generating rotation keys...")
    context.GenRotateKeys(keypair.privateKey)
    print("Done!")

    # Saving keys to file
    context.save("keys/context")
    context.saveMultKeys("keys/multKeys")
    context.saveRotKeys("keys/rotKeys")

    keypair.publicKey.save("keys/publicKey")
    keypair.privateKey.save("keys/privateKey")


if __name__ == "__main__":
    main()
