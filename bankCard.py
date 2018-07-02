# encoding:utf-8
# Class represents bank debet/credit card

class Card:
	def __init__(self,
				card_holder_name='Ivan Ivanov',
				card_number='0000000000000000',
				card_valid_date='12/18',
				card_cvv='000'):
		self.card_holder_name = card_holder_name
		self.card_number = card_number
		self.card_valid_date = card_valid_date
		self.card_cvv = card_cvv

	def __repr__(self):
		return '[Card: cardholder name = {}\n number = {}\n card valid until {}\n cvv = {}\n]'.format(self.card_holder_name, self.card_number, self.card_valid_date, self.card_cvv)


if __name__ == '__main__':
	k = Card()
	print(k)
